import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import assert from 'node:assert';
import { Buffer } from 'node:buffer';
import { getSessionId } from '../lib/session.js';
import { CoseKey, coseToJwk } from '../lib/cose.js';
import { getCurrentTimestamp, isBitFlagSet } from '../lib/util.js';
import { PasskeyData, User, database } from '../lib/database.js';
import { RP_ID_HASH } from '../lib/config.js';
import { decode } from 'cbor-x/decode';
import { AuthData, ClientData, FLAG_BACKUP_ELIGIBILITY, FLAG_BACKUP_STATE, FLAG_USER_VERIFIED, parseAuthData, validateAuthData, validateClientData } from '../lib/webauthn.js';

interface RequestBody {
    userId: Buffer;
    username: string;
    displayName: string;
    passkey: {
        clientData: ClientData;
        attestationObject: AttestationObject;
        transports: string[];
    };
}

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

function parseSignUpBody(body: string): RequestBody {
    const parameters = new URLSearchParams(body);

    const username = parameters.get('username');
    const displayName = parameters.get('displayName');
    const passkeyJSON = parameters.get('passkey');

    assert(username != null);
    assert(displayName != null);
    assert(passkeyJSON != null);

    const passkey = JSON.parse(passkeyJSON);
    const attestationObject = decodeAttestationObject(Buffer.from(passkey.attestationObject, 'base64'));

    return {
        userId: Buffer.from(passkey.userId, 'base64url'),
        username,
        displayName,
        passkey: {
            clientData: passkey.clientData,
            attestationObject,
            transports: passkey.transports
        }
    };
}

function createUserObject(requestBody: RequestBody): User {
    return {
        id: requestBody.userId,
        name: requestBody.username,
        displayName: requestBody.displayName,
        passkeys: new Set(),
        sessions: new Set()
    };
}

function createPasskeyObject(requestBody: RequestBody, publicKey: JsonWebKey): PasskeyData {
    return {
        type: 'public-key',
        credentialId: requestBody.passkey.attestationObject.credentialId!,
        userId: requestBody.userId,
        publicKey,
        signCount: requestBody.passkey.attestationObject.signCount,
        uvInitialized: isBitFlagSet(requestBody.passkey.attestationObject.flags, FLAG_USER_VERIFIED),
        transports: requestBody.passkey.transports,
        backupEligible: isBitFlagSet(requestBody.passkey.attestationObject.flags, FLAG_BACKUP_ELIGIBILITY),
        backupState: isBitFlagSet(requestBody.passkey.attestationObject.flags, FLAG_BACKUP_STATE),
        description: 'Added during account creation',
        createdTimestamp: getCurrentTimestamp()
    };
}

export async function createUser(bodyString: string, sessionId: string) {
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

    const user = createUserObject(body);
    const passkey = createPasskeyObject(body, jwk);

    // Store the user first because storing the passkey also updates the user data with the passkey's ID.
    await database.insertUser(user);
    await database.insertPasskey(passkey);
    console.log('Stored user', user, 'and passkey', passkey);

    await database.updateSessionUserId(sessionId, user.id);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null);

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    await createUser(event.body, sessionId);

    const response = {
        statusCode: 302,
        headers: {
            'Location': '/'
        },
    };

    return response;
};
