import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import assert from 'node:assert';
import { getSessionId } from '../lib/session.js';
import { webcrypto } from 'node:crypto';
import { database } from '../lib/database.js';
import { FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, parseAuthData, validateAuthData, validateClientData } from '../lib/webauthn.js';
import { RP_ID_HASH } from '../lib/config.js';
import { isBitFlagSet, sha256 } from '../lib/util.js';

interface SignInBody {
    id: Buffer;
    clientDataJSON: string;
    signature: Buffer;
    userHandle: Buffer;
    authenticatorData: Buffer;
}

function parseSignInBody(body: string): SignInBody {
    const parameters = new URLSearchParams(body);
    const passkeyJSON = parameters.get('passkey');
    assert(passkeyJSON !== null);
    const passkey = JSON.parse(passkeyJSON);

    return {
        id: Buffer.from(passkey.id, 'base64url'),
        clientDataJSON: passkey.clientDataJSON,
        signature: Buffer.from(passkey.signature, 'base64'),
        userHandle: Buffer.from(passkey.userHandle, 'base64'),
        authenticatorData: Buffer.from(passkey.authenticatorData, 'base64')
    };
}

function getImportAlgorithm(jwk: JsonWebKey): RsaHashedImportParams | EcKeyImportParams {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', namedCurve: 'P-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

function getVerifyAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | EcdsaParams {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', hash: 'SHA-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

async function verify(jwk: JsonWebKey, signature: Buffer, signedData: Buffer): Promise<boolean> {
    const importAlgorithm = getImportAlgorithm(jwk);
    const publicKey = await webcrypto.subtle.importKey('jwk', jwk, importAlgorithm, true, ['verify']);

    const verifyAlgorithm = getVerifyAlgorithm(jwk);
    return webcrypto.subtle.verify(verifyAlgorithm, publicKey, signature, signedData);
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

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null);

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    const isValid = await handleSignIn(event.body, sessionId);

    let response;
    if (isValid) {
        response = {
            statusCode: 302,
            headers: {
                'Location': '/'
            },
        };
    } else {
        response = {
            statusCode: 400,
            headers: {
                'Content-Type': 'text/html'
            },
            body: '<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Authentication failed!</p></body></html>'
        }
    }

    return response;
};
