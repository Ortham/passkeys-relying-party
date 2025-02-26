import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import assert from 'node:assert';
import { Buffer } from 'node:buffer';
import { getSessionId } from '../lib/session.js';
import { webcrypto } from 'node:crypto';
import { database } from '../lib/database.js';
import {
    FLAG_BACKUP_ELIGIBILITY,
    FLAG_BACKUP_STATE,
    assertIsClientData,
    parseAuthData,
    validateAuthData,
    validateClientData,
} from '../lib/webauthn.js';
import { RP_ID_HASH } from '../lib/config.js';
import { isBitFlagSet, sha256 } from '../lib/util.js';

interface SignInBody {
    id: Buffer;
    clientDataJSON: Buffer;
    signature: Buffer;
    userHandle: Buffer | undefined;
    authenticatorData: Buffer;
}

interface SignInBodyJson {
    id: string;
    clientDataJSON: string;
    signature: string;
    userHandle: string | undefined;
    authenticatorData: string;
}

function assertParsedJsonIsValid(
    value: unknown,
): asserts value is SignInBodyJson {
    assert.strictEqual(typeof value, 'object', 'Value is not an object');
    assert(value !== null, 'Value is null');

    const rbValue = value as SignInBodyJson;

    assert.strictEqual(typeof rbValue.id, 'string', 'id is not a string');
    assert.strictEqual(
        typeof rbValue.clientDataJSON,
        'string',
        'clientDataJSON is not a string',
    );
    assert.strictEqual(
        typeof rbValue.signature,
        'string',
        'signature is not a string',
    );

    assert(
        rbValue.userHandle === undefined ||
            typeof rbValue.userHandle === 'string',
        'userHandle is defined but not a string',
    );

    assert.strictEqual(
        typeof rbValue.authenticatorData,
        'string',
        'authenticatorData is not a string',
    );
}

function parseRequestBody(body: string): SignInBody {
    const parsed: unknown = JSON.parse(body);

    assertParsedJsonIsValid(parsed);

    return {
        id: Buffer.from(parsed.id, 'base64url'),
        clientDataJSON: Buffer.from(parsed.clientDataJSON, 'base64'),
        signature: Buffer.from(parsed.signature, 'base64'),
        authenticatorData: Buffer.from(parsed.authenticatorData, 'base64'),
        userHandle: parsed.userHandle
            ? Buffer.from(parsed.userHandle, 'base64')
            : undefined,
    };
}

function getImportAlgorithm(
    jwk: JsonWebKey,
): RsaHashedImportParams | EcKeyImportParams {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', namedCurve: 'P-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

function getVerifyAlgorithm(
    jwk: JsonWebKey,
): AlgorithmIdentifier | EcdsaParams {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', hash: 'SHA-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

function fixPadding(buffer: Buffer, targetLength: number) {
    while (buffer.byteLength > targetLength) {
        buffer = buffer.subarray(1);
    }

    if (buffer.byteLength < targetLength) {
        const prefix = Buffer.alloc(targetLength - buffer.byteLength, 0);
        buffer = Buffer.concat([prefix, buffer]);
    }

    return buffer;
}

function readDerInteger(
    buffer: Buffer,
    expectedValueLength: number,
): { value: Buffer; end: number } {
    const DER_TAG_INTEGER = 0x02;

    assert.strictEqual(
        buffer[0],
        DER_TAG_INTEGER,
        'The DER buffer does not start with an integer',
    );

    const valueLength = buffer[1];
    assert(
        valueLength !== undefined,
        'The DER buffer is shorter than expected',
    );

    const start = 2;
    const end = start + valueLength;

    // Some clients don't pad the values correctly.
    const value = fixPadding(buffer.subarray(start, end), expectedValueLength);

    return {
        value,
        end,
    };
}

function decodeEcdsaSignature(
    signature: Buffer,
    expectedSignatureLength: number,
): Buffer {
    const DER_TAG_SEQUENCE = 0x30;

    assert.strictEqual(
        signature[0],
        DER_TAG_SEQUENCE,
        'The DER buffer does not start with a sequence',
    );
    assert.strictEqual(
        signature[1],
        signature.byteLength - 2,
        'The DER sequence length does not match the buffer size',
    );

    assert.strictEqual(
        expectedSignatureLength % 2,
        0,
        'Invalid expected signature length',
    );

    const expectedValueLength = expectedSignatureLength / 2;

    const start = 2;
    const { value: r, end } = readDerInteger(
        signature.subarray(start),
        expectedValueLength,
    );
    const { value: s } = readDerInteger(
        signature.subarray(start + end),
        expectedValueLength,
    );

    return Buffer.concat([r, s]);
}

function prepareSignature(jwk: JsonWebKey, signature: Buffer): Buffer {
    if (jwk.alg === 'RS256') {
        return signature;
    }

    if (jwk.alg === 'ES256') {
        // An ECDSA signature is encoded as an ASN.1 DER Ecdsa-Sig-Value (WebAuthn spec section 6.5.6), but webcrypto.subtle.verify expects a raw 64-byte signature.
        return decodeEcdsaSignature(signature, 64);
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

async function verify(
    jwk: JsonWebKey,
    signature: Buffer,
    signedData: Buffer,
): Promise<boolean> {
    const importAlgorithm = getImportAlgorithm(jwk);
    const publicKey = await webcrypto.subtle.importKey(
        'jwk',
        jwk,
        importAlgorithm,
        false,
        ['verify'],
    );

    const verifyAlgorithm = getVerifyAlgorithm(jwk);
    const preparedSignature = prepareSignature(jwk, signature);
    return webcrypto.subtle.verify(
        verifyAlgorithm,
        publicKey,
        preparedSignature,
        signedData,
    );
}

export async function handleSignIn(bodyString: string, sessionId: string) {
    const body = parseRequestBody(bodyString);
    console.log('Request body is', body);

    assert(
        body.userHandle !== undefined,
        'User handle is not in the request body',
    );

    const passkey = await database.getPasskeyData(body.id);
    assert(passkey !== undefined, 'No stored passkey found with the given ID');
    console.log('Retrieved passkey data', passkey);
    assert(
        body.userHandle.equals(passkey.userHandle),
        'The given user handle does not match the stored user handle for this credential',
    );

    const clientData: unknown = JSON.parse(
        body.clientDataJSON.toString('utf8'),
    );
    assertIsClientData(clientData);

    const expectedChallenge = await database.getAndDeleteChallenge(sessionId);
    assert(expectedChallenge !== undefined, 'No stored challenge found');

    validateClientData(clientData, 'webauthn.get', expectedChallenge);

    const authData = parseAuthData(body.authenticatorData);

    validateAuthData(authData, await RP_ID_HASH, false);

    const isBackupEligible = isBitFlagSet(
        authData.flags,
        FLAG_BACKUP_ELIGIBILITY,
    );
    assert.strictEqual(
        isBackupEligible,
        passkey.backupEligible,
        'Backup Eligiblity state has changed',
    );

    // Don't care about backup eligibility or state beyond basic validation.
    // Don't care about client extensions.

    const hash = await sha256(body.clientDataJSON);
    const signedData = Buffer.concat([
        body.authenticatorData,
        Buffer.from(hash),
    ]);

    const isValid = await verify(passkey.publicKey, body.signature, signedData);

    if (isValid) {
        console.log('Authentication successful!');

        if (authData.signCount < passkey.signCount) {
            console.warn(
                'The stored sign count is greater than the given sign count, the authenticator may be cloned',
            );
        }

        // No need to update uvInitialised as it's required to be true initially.
        assert(passkey.uvInitialized, 'uvInitialized is not already true');

        const isBackedUp = isBitFlagSet(authData.flags, FLAG_BACKUP_STATE);
        await database.updatePasskeyState(
            body.id,
            authData.signCount,
            isBackedUp,
        );

        await database.updateSessionUserId(sessionId, passkey.userId);
    } else {
        console.error('Authentication failed!');
    }

    return isValid;
}

export const lambdaHandler: Handler = async (
    event: APIGatewayProxyEvent,
    _context,
) => {
    assert(event.body !== null, 'The request has no body');

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined, 'The request has no session ID');

    const isValid = await handleSignIn(event.body, sessionId);

    let response;
    if (isValid) {
        response = {
            statusCode: 204,
        };
    } else {
        response = {
            statusCode: 400,
        };
    }

    return response;
};
