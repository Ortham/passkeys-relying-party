import assert from 'node:assert';
import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { AuthData, ClientData, FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, FLAG_USER_VERIFIED, parseAuthData, validateAuthData, validateClientData } from '../lib/webauthn.js';
import { CoseKey, coseToJwk } from '../lib/cose.js';
import { getSessionId } from '../lib/session.js';
import { PasskeyData, User, database } from '../lib/database.js';
import { RP_ID_HASH } from '../lib/config.js';
import { getCurrentTimestamp, isBitFlagSet } from '../lib/util.js';
import { parseAttestationObject } from '../lib/cbor.js';


interface AttestationObject extends AuthData {
    fmt: unknown;
    attStmt: Map<unknown, unknown>;
}

interface ValidatedAttestationObject extends AttestationObject {
    fmt: 'none';
    attStmt: Map<unknown, unknown>;
    aaguid: Buffer;
    credentialIdLength: number;
    credentialId: Buffer;
    credentialPublicKey: CoseKey;
}

export interface RequestBody {
    clientData: ClientData;
    attestationObject: AttestationObject;
    transports: string[];
    description: string;
}


function decodeAttestationObject(attestationObject: Buffer): AttestationObject {
    // https://w3c.github.io/webauthn/#attestation-object
    const { fmt, attStmt, authData } = parseAttestationObject(attestationObject);

    return { fmt, attStmt, ...parseAuthData(authData) };
}

function validateAttestationObject(attestationObject: AttestationObject, expectedRpIdHash: ArrayBuffer): asserts attestationObject is ValidatedAttestationObject {
    assert.strictEqual(attestationObject.fmt, 'none', 'Assertion format is not none');
    assert.strictEqual(attestationObject.attStmt.size, 0, 'Assertion statement is not empty');

    validateAuthData(attestationObject, expectedRpIdHash, true);
}

export function parseRequestBody(body: string): RequestBody {
    const passkey = JSON.parse(body);
    const attestationObject = decodeAttestationObject(Buffer.from(passkey.attestationObject, 'base64'));

    return {
        clientData: passkey.clientData,
        attestationObject,
        transports: passkey.transports,
        description: passkey.description
    };
}

export function createPasskeyObject(requestBody: Omit<RequestBody, 'clientData' | 'description'>, user: Pick<User, 'id' | 'userHandle'>, publicKey: JsonWebKey, description: string): PasskeyData {
    return {
        type: 'public-key',
        credentialId: requestBody.attestationObject.credentialId!,
        userId: user.id,
        userHandle: user.userHandle,
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

export async function validatePasskeyInputs(passkey: Omit<RequestBody, 'description' | 'transports'>, sessionId: string): Promise<JsonWebKey> {
    // https://w3c.github.io/webauthn/#sctn-registering-a-new-credential

    const expectedChallenge = await database.getAndDeleteChallenge(sessionId);
    assert(expectedChallenge !== undefined, 'No stored challenge found');

    validateClientData(passkey.clientData, 'webauthn.create', expectedChallenge);

    validateAttestationObject(passkey.attestationObject, await RP_ID_HASH);

    // Don't care about backup eligibility or backup state beyond validation.
    // Don't care about client extensions.

    const passkeyExists = await database.passkeyExists(passkey.attestationObject.credentialId);
    assert(!passkeyExists, 'No stored passkey with the given credential ID');

    return coseToJwk(passkey.attestationObject.credentialPublicKey);
}

export async function createPasskey(bodyString: string, sessionId: string, user: Pick<User, 'id' | 'userHandle'>) {

    const body = parseRequestBody(bodyString);
    console.log('Request body is', body);

    const jwk = await validatePasskeyInputs(body, sessionId);
    const passkey = createPasskeyObject(body, user, jwk, body.description);

    await database.insertPasskey(passkey);
    console.log('Stored passkey', passkey);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null, 'The request has no body');

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined, 'The request has no session ID');

    const user = await database.getUserBySessionId(sessionId);
    assert(user !== undefined, 'No user found for the given session ID');

    await createPasskey(event.body, sessionId, user);

    const response = {
        statusCode: 200
    };

    return response;
};
