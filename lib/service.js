import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import { database } from './database.js';
import { FLAG_USER_VERIFIED, FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, validateClientData, validateFlags, parseAuthData, parseSignUpBody, validateRpIdHash, coseToJwk, getAlgorithm, parseSignInBody } from './webauthn.js';
import { isBitFlagSet, sha256 } from './util.js';

function getRandomBytes(count) {
    const array = new Uint8Array(count);
    webcrypto.getRandomValues(array);

    return Buffer.from(array.buffer);
}

export function createSessionId() {
    return getRandomBytes(16).toString('base64');
}

export function createChallenge(sessionId) {
    const challenge = getRandomBytes(16);

    database.insertChallenge(sessionId, challenge);

    return challenge.toString('base64url');
}

export function createNewUserId() {
    // TODO: Come up with a better way of handling user ID generation.
    // Would be better to insert this into the DB now in case of collisions.
    return getRandomBytes(16).toString('base64url');
}

function createUser(signUpBody, publicKey, algorithm) {
    return {
        id: signUpBody.userId,
        name: signUpBody.username,
        displayName: signUpBody.displayName,
        passkey: {
            id: signUpBody.passkey.id,
            publicKey,
            algorithm,
            signCount: signUpBody.passkey.attestationObject.signCount,
            uvInitialized: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_USER_VERIFIED),
            transports: signUpBody.passkey.transports,
            backupEligible: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_BACKUP_ELIGIBILITY),
            backupState: isBitFlagSet(signUpBody.passkey.attestationObject.flags, FLAG_BACKUP_STATE)
        }
    };
}

export async function handleSignUp(bodyBuffer, sessionId) {
    const body = parseSignUpBody(bodyBuffer);
    console.log('Request body is', body);

    const expectedChallenge = database.getChallenge(sessionId);

    validateClientData(body.passkey.clientData, 'webauthn.create', expectedChallenge);

    await validateRpIdHash(body.passkey.attestationObject.rpIdHash);

    // Don't care about backup eligibility or backup state beyond validation.
    // Don't care about client extensions.

    assert(body.passkey.attestationObject.credentialIdLength <= 1023, 'Credential ID is greater than 1023 bytes long');

    const matchingCredentialIdCount = database.countUsersByCredentialId(body.passkey.attestationObject.credentialId);
    assert.strictEqual(matchingCredentialIdCount, 0);

    const jwk = coseToJwk(body.passkey.attestationObject.credentialPublicKey);
    const algorithm = getAlgorithm(jwk);

    const publicKey = await webcrypto.subtle.importKey('jwk', jwk, algorithm, true, ['verify']);

    const user = createUser(body, publicKey, algorithm);

    database.insertUser(user);
    console.log('Stored user', user);
}

export async function handleSignIn(bodyBuffer, sessionId) {
    const body = parseSignInBody(bodyBuffer);
    console.log('Request body is', body);

    const user = database.getUser(body.userHandle);
    console.log('Retrieved user data', user);

    assert.strictEqual(body.id, user.passkey.id);

    const clientData = JSON.parse(body.clientDataJSON);

    const expectedChallenge = database.getChallenge(sessionId);

    validateClientData(clientData, 'webauthn.get', expectedChallenge);

    const authData = parseAuthData(body.authenticatorData, false);

    await validateRpIdHash(authData.rpIdHash);

    validateFlags(authData.flags);

    const isBackupEligible = isBitFlagSet(authData.flags, FLAG_BACKUP_ELIGIBILITY);
    assert.strictEqual(isBackupEligible, user.passkey.backupEligible, "Backup Eligiblity state has changed");

    // Don't care about backup eligibility or state beyond basic validation.
    // Don't care about client extensions.

    const hash = await sha256(Buffer.from(body.clientDataJSON, 'utf-8'));
    const signedData = Buffer.concat([body.authenticatorData, Buffer.from(hash)]);

    const isValid = await webcrypto.subtle.verify(user.passkey.algorithm, user.passkey.publicKey, body.signature, signedData);

    if (isValid) {
        console.log('Authentication successful!');

        if (authData.signCount < user.passkey.signCount) {
            console.warn('The stored sign count is greater than the given sign count, the authenticator may be cloned');
        }

        // No need to update uvInitialised as it's required to be true initially.
        assert(user.passkey.uvInitialized);

        const isBackedUp = isBitFlagSet(authData.flags, FLAG_BACKUP_STATE);
        database.updatePasskeyState(body.userHandle, authData.signCount, isBackedUp);

        // TODO: Update session to indicate that the user is authenticated.
    } else {
        console.error('Authentication failed!');
    }

    return isValid;
}
