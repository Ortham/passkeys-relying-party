import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import { RP_ID } from './config.js';
import { User, database } from './database.js';
import { FLAG_USER_VERIFIED, FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, validateClientData, parseAuthData, parseSignUpBody, coseToJwk, parseSignInBody, validateAuthData, validateAttestationObject, SignUpBody, verify } from './webauthn.js';
import { isBitFlagSet, sha256 } from './util.js';

function getRandomBytes(count: number) {
    const array = new Uint8Array(count);
    webcrypto.getRandomValues(array);

    return Buffer.from(array.buffer);
}

export async function isValidSessionId(sessionId: string) {
    if (sessionId === undefined) {
        return false;
    }

    return database.sessionExists(sessionId);
}

export async function createSession() {
    const sessionId = getRandomBytes(16).toString('base64url');

    await database.insertSession(sessionId);

    return sessionId;
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

function createUser(signUpBody: SignUpBody, publicKey: JsonWebKey): User {
    return {
        id: signUpBody.userId,
        name: signUpBody.username,
        displayName: signUpBody.displayName,
        passkey: {
            type: 'public-key',
            id: signUpBody.passkey.id,
            publicKey,
            signCount: signUpBody.passkey.attestationObject.signCount,
            uvInitialized: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_USER_VERIFIED),
            transports: signUpBody.passkey.transports,
            backupEligible: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_BACKUP_ELIGIBILITY),
            backupState: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_BACKUP_STATE)
        }
    };
}

export async function logout(sessionId: string) {
    database.deleteSession(sessionId);
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

    const expectedRpIdHash = await sha256(RP_ID);
    validateAttestationObject(body.passkey.attestationObject, expectedRpIdHash);

    // Don't care about backup eligibility or backup state beyond validation.
    // Don't care about client extensions.

    const credentialExists = await database.credentialExists(body.passkey.attestationObject.credentialId);
    assert(!credentialExists);

    const jwk = coseToJwk(body.passkey.attestationObject.credentialPublicKey);

    const user = createUser(body, jwk);

    await database.insertUser(user);
    console.log('Stored user', user);

    await database.updateSessionUserId(sessionId, user.id);
}

export async function handleSignIn(bodyString: string, sessionId: string) {
    const body = parseSignInBody(bodyString);
    console.log('Request body is', body);

    const user = await database.getUser(body.userHandle);
    assert(user !== undefined);
    console.log('Retrieved user data', user);

    assert.strictEqual(body.id, user.passkey.id);

    const clientData = JSON.parse(body.clientDataJSON);

    const expectedChallenge = await database.getChallenge(sessionId);
    assert(expectedChallenge !== undefined);

    validateClientData(clientData, 'webauthn.get', expectedChallenge);

    const authData = parseAuthData(body.authenticatorData);

    const expectedRpIdHash = await sha256(RP_ID);
    validateAuthData(authData, expectedRpIdHash, false);

    const isBackupEligible = isBitFlagSet(authData.flags, FLAG_BACKUP_ELIGIBILITY);
    assert.strictEqual(isBackupEligible, user.passkey.backupEligible, "Backup Eligiblity state has changed");

    // Don't care about backup eligibility or state beyond basic validation.
    // Don't care about client extensions.

    const hash = await sha256(Buffer.from(body.clientDataJSON, 'utf-8'));
    const signedData = Buffer.concat([body.authenticatorData, Buffer.from(hash)]);

    const isValid = await verify(user.passkey.publicKey, body.signature, signedData);

    if (isValid) {
        console.log('Authentication successful!');

        if (authData.signCount < user.passkey.signCount) {
            console.warn('The stored sign count is greater than the given sign count, the authenticator may be cloned');
        }

        // No need to update uvInitialised as it's required to be true initially.
        assert(user.passkey.uvInitialized);

        const isBackedUp = isBitFlagSet(authData.flags, FLAG_BACKUP_STATE);
        await database.updatePasskeyState(body.userHandle, authData.signCount, isBackedUp);

        await database.updateSessionUserId(sessionId, body.userHandle);
    } else {
        console.error('Authentication failed!');
    }

    return isValid;
}
