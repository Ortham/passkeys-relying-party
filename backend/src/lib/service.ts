import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import { RP_ID_HASH, SESSION_COOKIE_NAME } from './config.js';
import { PasskeyData, User, database } from './database.js';
import { FLAG_USER_VERIFIED, FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, validateClientData, parseAuthData, parseSignUpBody, coseToJwk, parseSignInBody, validateAuthData, validateAttestationObject, SignUpBody, verify } from './webauthn.js';
import { getCookies, isBitFlagSet, sha256 } from './util.js';

function getRandomBytes(count: number) {
    const array = new Uint8Array(count);
    webcrypto.getRandomValues(array);

    return Buffer.from(array.buffer);
}

function isValidSessionId(sessionId: string | undefined) {
    if (sessionId === undefined) {
        return false;
    }

    return database.sessionExists(sessionId);
}

async function createSession() {
    const sessionId = getRandomBytes(16).toString('base64url');

    await database.insertSession(sessionId);

    return sessionId;
}

export function getSessionId(requestHeaders: Record<string, string | string[] | undefined>) {
    return getCookies(requestHeaders).get(SESSION_COOKIE_NAME);
}

export async function getOrCreateSession(requestHeaders: Record<string, string | string[] | undefined>) {
    let sessionId = getSessionId(requestHeaders);
    const isValid = await isValidSessionId(sessionId);

    let responseHeaders: Record<string, string> | undefined;
    if (!isValid) {
        console.warn('Session ID', sessionId, 'is not valid, creating new session');
        sessionId = await createSession();
        responseHeaders = {
            'Set-Cookie': `${SESSION_COOKIE_NAME}=${sessionId}; HttpOnly; SameSite=Strict; Secure`
        };
    }

    return {
        sessionId: sessionId!,
        responseHeaders
    };
}

export async function createChallenge(sessionId: string) {
    const challenge = getRandomBytes(16);

    await database.updateSessionChallenge(sessionId, challenge);

    return challenge.toString('base64url');
}

export function createNewUserId() {
    // TODO: Come up with a better way of handling user ID generation.
    // Would be better to insert this into the DB now in case of collisions.
    return getRandomBytes(16).toString('base64url');
}

function createUser(signUpBody: SignUpBody): User {
    return {
        id: signUpBody.userId,
        name: signUpBody.username,
        displayName: signUpBody.displayName
    };
}

function createPasskey(signUpBody: SignUpBody, publicKey: JsonWebKey): PasskeyData {
    return {
        type: 'public-key',
        credentialId: signUpBody.passkey.attestationObject.credentialId!,
        userId: signUpBody.userId,
        publicKey,
        signCount: signUpBody.passkey.attestationObject.signCount,
        uvInitialized: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_USER_VERIFIED),
        transports: signUpBody.passkey.transports,
        backupEligible: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_BACKUP_ELIGIBILITY),
        backupState: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_BACKUP_STATE)
    };
}

export async function logout(sessionId: string) {
    await database.deleteSession(sessionId);

    return {
        'Set-Cookie': `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Secure; Max-Age=0`
    };
}

export async function getProfile(sessionId: string) {
    const user = await database.getUserBySessionId(sessionId);
    if (!user) {
        return undefined;
    }

    return {
        username: user.name,
        displayName: user.displayName
    };
}

export async function handleSignUp(bodyString: string, sessionId: string) {
    const body = parseSignUpBody(bodyString);
    console.log('Request body is', body);

    const expectedChallenge = await database.getChallenge(sessionId);
    assert(expectedChallenge !== undefined);

    validateClientData(body.passkey.clientData, 'webauthn.create', expectedChallenge);

    validateAttestationObject(body.passkey.attestationObject, await RP_ID_HASH);

    // Don't care about backup eligibility or backup state beyond validation.
    // Don't care about client extensions.

    const passkeyExists = await database.passkeyExists(body.passkey.attestationObject.credentialId);
    assert(!passkeyExists);

    const jwk = coseToJwk(body.passkey.attestationObject.credentialPublicKey);

    const user = createUser(body);
    const passkey = createPasskey(body, jwk);

    await Promise.all([database.insertUser(user), database.insertPasskey(passkey)]);
    console.log('Stored user', user, 'and passkey', passkey);

    await database.updateSessionUserId(sessionId, user.id);
}

export async function handleSignIn(bodyString: string, sessionId: string) {
    const body = parseSignInBody(bodyString);
    console.log('Request body is', body);

    const passkey = await database.getPasskeyData(body.id);
    assert(passkey !== undefined);
    console.log('Retrieved passkey data', passkey);
    assert(passkey.userId.equals(body.userHandle));

    const clientData = JSON.parse(body.clientDataJSON);

    const expectedChallenge = await database.getChallenge(sessionId);
    assert(expectedChallenge !== undefined);

    validateClientData(clientData, 'webauthn.get', expectedChallenge);

    const authData = parseAuthData(body.authenticatorData);

    validateAuthData(authData, await RP_ID_HASH, false);

    const isBackupEligible = isBitFlagSet(authData.flags, FLAG_BACKUP_ELIGIBILITY);
    assert.strictEqual(isBackupEligible, passkey.backupEligible, "Backup Eligiblity state has changed");

    // Don't care about backup eligibility or state beyond basic validation.
    // Don't care about client extensions.

    const hash = await sha256(Buffer.from(body.clientDataJSON, 'utf-8'));
    const signedData = Buffer.concat([body.authenticatorData, Buffer.from(hash)]);

    const isValid = await verify(passkey.publicKey, body.signature, signedData);

    if (isValid) {
        console.log('Authentication successful!');

        if (authData.signCount < passkey.signCount) {
            console.warn('The stored sign count is greater than the given sign count, the authenticator may be cloned');
        }

        // No need to update uvInitialised as it's required to be true initially.
        assert(passkey.uvInitialized);

        const isBackedUp = isBitFlagSet(authData.flags, FLAG_BACKUP_STATE);
        await database.updatePasskeyState(body.id, authData.signCount, isBackedUp);

        await database.updateSessionUserId(sessionId, body.userHandle);
    } else {
        console.error('Authentication failed!');
    }

    return isValid;
}
