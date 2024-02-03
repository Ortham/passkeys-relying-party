import assert from 'node:assert';
import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { decode } from 'cbor-x/decode';
import { AuthData, ClientData, FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, FLAG_USER_VERIFIED, parseAuthData, validateAuthData, validateClientData } from '../lib/webauthn.js';
import { CoseKey, coseToJwk } from '../lib/cose.js';
import { getSessionId } from '../lib/session.js';
import { PasskeyData, database } from '../lib/database.js';
import { RP_ID_HASH } from '../lib/config.js';
import { getCurrentTimestamp, isBitFlagSet } from '../lib/util.js';


interface AttestationObject extends AuthData {
    fmt: unknown;
    attStmt: unknown;
}

interface ValidatedAttestationObject extends AttestationObject {
    fmt: 'none';
    attStmt: {};
    aaguid: Buffer;
    credentialIdLength: number;
    credentialId: Buffer;
    credentialPublicKey: CoseKey;
}

export interface RequestBody {
    userId: Buffer;
    clientData: ClientData;
    attestationObject: AttestationObject;
    transports: string[];
    description: string;
}


function decodeAttestationObject(attestationObject: Buffer): AttestationObject {
    // https://w3c.github.io/webauthn/#attestation-object
    const { fmt, attStmt, authData } = decode(attestationObject);

    return { fmt, attStmt, ...parseAuthData(authData) };
}

function validateAttestationObject(attestationObject: AttestationObject, expectedRpIdHash: ArrayBuffer): asserts attestationObject is ValidatedAttestationObject {
    assert.strictEqual(attestationObject.fmt, 'none');
    assert(typeof attestationObject.attStmt === 'object' && attestationObject.attStmt !== null);
    assert.strictEqual(Object.keys(attestationObject.attStmt).length, 0);

    validateAuthData(attestationObject, expectedRpIdHash, true);
}

export function parseRequestBody(body: string): RequestBody {
    const passkey = JSON.parse(body);
    const attestationObject = decodeAttestationObject(Buffer.from(passkey.attestationObject, 'base64'));

    return {
        userId: Buffer.from(passkey.userId, 'base64url'),
        clientData: passkey.clientData,
        attestationObject,
        transports: passkey.transports,
        description: passkey.description
    };
}

export function createPasskeyObject(requestBody: Omit<RequestBody, 'clientData' | 'description'>, publicKey: JsonWebKey, description: string): PasskeyData {
    return {
        type: 'public-key',
        credentialId: requestBody.attestationObject.credentialId!,
        userId: requestBody.userId,
        publicKey,
        signCount: requestBody.attestationObject.signCount,
        uvInitialized: isBitFlagSet(requestBody.attestationObject.flags, FLAG_USER_VERIFIED),
        transports: requestBody.transports,
        backupEligible: isBitFlagSet(requestBody.attestationObject.flags, FLAG_BACKUP_ELIGIBILITY),
        backupState: isBitFlagSet(requestBody.attestationObject.flags, FLAG_BACKUP_STATE),
        description,
        createdTimestamp: getCurrentTimestamp()
    };
}

export async function validatePasskeyInputs(passkey: Omit<RequestBody, 'description' | 'transports'>, sessionId: string, expectedUserId: Buffer): Promise<JsonWebKey> {
    // https://w3c.github.io/webauthn/#sctn-registering-a-new-credential

    // Important to validate this when adding a passkey for an existing user so that they can't add
    // their passkey to a different user's account.
    assert(expectedUserId.equals(passkey.userId));

    const expectedChallenge = await database.getChallenge(sessionId);
    assert(expectedChallenge !== undefined);

    validateClientData(passkey.clientData, 'webauthn.create', expectedChallenge);

    validateAttestationObject(passkey.attestationObject, await RP_ID_HASH);

    // Don't care about backup eligibility or backup state beyond validation.
    // Don't care about client extensions.

    const passkeyExists = await database.passkeyExists(passkey.attestationObject.credentialId);
    assert(!passkeyExists);

    return coseToJwk(passkey.attestationObject.credentialPublicKey);
}

export async function createPasskey(bodyString: string, sessionId: string, expectedUserId: Buffer) {

    const body = parseRequestBody(bodyString);
    console.log('Request body is', body);

    const jwk = await validatePasskeyInputs(body, sessionId, expectedUserId);
    const passkey = createPasskeyObject(body, jwk, body.description);

    await database.insertPasskey(passkey);
    console.log('Stored passkey', passkey);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null);

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    const user = await database.getUserBySessionId(sessionId);
    assert(user !== undefined);

    await createPasskey(event.body, sessionId, user.id);

    const response = {
        statusCode: 200
    };

    return response;
};
