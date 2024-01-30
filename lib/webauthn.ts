import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { decode, decodeMultiple } from 'cbor-x/decode';
import { PORT } from './config.js';
import { isBitFlagSet } from './util.js';
import { webcrypto } from 'node:crypto';

const FLAG_USER_PRESENT = 0b0001;
export const FLAG_USER_VERIFIED = 0b0100;
export const FLAG_BACKUP_ELIGIBILITY = 0b1000;
export const FLAG_BACKUP_STATE = 0b0001_0000;
const FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED = 0b0100_0000;
const FLAG_EXTENSION_DATA_INCLUDED = 0b1000_0000;

const WEBAUTHN_ALG_ES256 = -7;
const WEBAUTHN_ALG_RS256 = -257;
const COSE_EC_P256 = 1;
const COSE_KEY_TYPE_EC2 = 2;
const COSE_KEY_TYPE_RSA = 3;

interface ClientData {
    type: string;
    challenge: string;
    origin: string;
    topOrigin: unknown;
}

interface AuthData {
    rpIdHash: Buffer;
    flags: number;
    signCount: number;
    aaguid: Buffer | undefined;
    credentialIdLength: number | undefined;
    credentialId: Buffer | undefined;
    credentialPublicKey: unknown;
    extensions: unknown;
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

interface CoseKey {
    '1': number;
    '3': number;

    [key: string]: unknown;
}

interface EcCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_EC2;
    '3': typeof WEBAUTHN_ALG_ES256;
    '-1': typeof COSE_EC_P256;
    '-2': Buffer;
    '-3': Buffer;
}

interface RsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_RSA;
    '3': typeof WEBAUTHN_ALG_RS256;
    '-1': Buffer;
    '-2': Buffer;
}

export interface SignUpBody {
    userId: Buffer;
    username: string;
    displayName: string;
    passkey: {
        id: string;
        clientData: ClientData;
        attestationObject: AttestationObject;
        transports: string[];
    };
}

interface SignInBody {
    id: string;
    clientDataJSON: string;
    signature: Buffer;
    userHandle: Buffer;
    authenticatorData: Buffer;
}

export function validateClientData(clientData: ClientData, expectedType: string, expectedChallenge: Buffer) {
    const allowedOrigins = [`http://localhost:${PORT}`];

    assert.strictEqual(clientData.type, expectedType);
    assert.strictEqual(clientData.challenge, expectedChallenge.toString('base64url'));
    assert(allowedOrigins.includes(clientData.origin), `Origin ${clientData.origin} is not allowed`);
    assert.strictEqual(clientData.topOrigin, undefined);
}

function validateFlags(flags: number) {
    assert(isBitFlagSet(flags, FLAG_USER_PRESENT), 'User Present bit is not set');

    if (!isBitFlagSet(flags, FLAG_BACKUP_ELIGIBILITY)) {
        assert(!isBitFlagSet(flags, FLAG_BACKUP_STATE), 'Backup State bit is set but Backup Eligible bit is not set');
    }
}

function validatePublicKey(publicKey: unknown): asserts publicKey is CoseKey {
    assert(publicKey !== null);
    assert(typeof publicKey === 'object');
    assert('1' in publicKey);
    assert('3' in publicKey);
}

export function parseAuthData(authData: Buffer): AuthData {
    // https://w3c.github.io/webauthn/#sctn-attested-credential-data

    const rpIdHash = authData.subarray(0, 32);
    const flags = authData.readUint8(32);
    const signCount = authData.readUint32BE(33);

    validateFlags(flags);

    const hasCredentialData = isBitFlagSet(flags, FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED);
    const hasExtensionData = isBitFlagSet(flags, FLAG_EXTENSION_DATA_INCLUDED);

    let aaguid: Buffer | undefined;
    let credentialIdLength: number | undefined;
    let credentialId: Buffer | undefined;
    let credentialPublicKey: CoseKey | undefined;
    let extensions: unknown;
    if (hasCredentialData) {
        // Attested credential data fields.
        aaguid = authData.subarray(37, 53);
        credentialIdLength = authData.readUint16BE(53);
        credentialId = authData.subarray(55, 55 + credentialIdLength);

        // Next field is the credential public key, but it may be followed by an extensions map.
        // The TypeScript types for decodeMultiple are wrong.
        const remaining = decodeMultiple(authData.subarray(55 + credentialIdLength)) as unknown;
        assert(Array.isArray(remaining), "Auth data does not end with an array of CBOR entries");

        if (hasExtensionData) {
            assert.strictEqual(remaining.length, 2);

            credentialPublicKey = remaining[0];
            extensions = remaining[1];
        } else {
            assert.strictEqual(remaining.length, 1);

            credentialPublicKey = remaining[0];
        }

        validatePublicKey(credentialPublicKey);
    } else if (hasExtensionData) {
        const remaining = decodeMultiple(authData.subarray(37)) as unknown;
        assert(Array.isArray(remaining), "Auth data does not end with an array of CBOR entries");

        assert.strictEqual(remaining.length, 1);

        extensions = remaining[0];
    } else {
        assert.strictEqual(authData.length, 37);
    }

    return { rpIdHash, flags, signCount, aaguid, credentialIdLength, credentialId, credentialPublicKey, extensions };
}

function decodeAttestationObject(attestationObject: Buffer): AttestationObject {
    // https://w3c.github.io/webauthn/#attestation-object
    const { fmt, attStmt, authData } = decode(attestationObject);

    return { fmt, attStmt, ...parseAuthData(authData) };
}

export function validateAuthData(authData: AuthData, expectedRpIdHash: ArrayBuffer, requireCredentialData: boolean) {
    assert.strictEqual(authData.rpIdHash.toString('hex'), Buffer.from(expectedRpIdHash).toString('hex'));

    assert(isBitFlagSet(authData.flags, FLAG_USER_VERIFIED), 'User Verified bit is not set');

    if (requireCredentialData) {
        assert(isBitFlagSet(authData.flags, FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED), 'No attested credential data included');

        assert(authData.credentialIdLength !== undefined);
        assert(authData.credentialIdLength <= 1023, 'Credential ID is greater than 1023 bytes long');
    }
}

export function validateAttestationObject(attestationObject: AttestationObject, expectedRpIdHash: ArrayBuffer): asserts attestationObject is ValidatedAttestationObject {
    assert.strictEqual(attestationObject.fmt, 'none');
    assert(typeof attestationObject.attStmt === 'object' && attestationObject.attStmt !== null);
    assert.strictEqual(Object.keys(attestationObject.attStmt).length, 0);

    validateAuthData(attestationObject, expectedRpIdHash, true);
}

function isEcCoseKey(key: CoseKey): key is EcCoseKey {
    return key['1'] === COSE_KEY_TYPE_EC2
        && key['3'] === WEBAUTHN_ALG_ES256
        && key['-1'] === COSE_EC_P256
        && Buffer.isBuffer(key['-2'])
        && Buffer.isBuffer(key['-3']);
}

function isRsaCoseKey(key: CoseKey): key is RsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_RSA
        && key['3'] === WEBAUTHN_ALG_RS256
        && Buffer.isBuffer(key['-1'])
        && Buffer.isBuffer(key['-2']);
}

function ecCoseToJwk(key: EcCoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    return {
        kty: 'EC',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'ES256',
        crv: 'P-256',
        x: key['-2'].toString('base64url'),
        y: key['-3'].toString('base64url')
    };
}

function rsaCoseToJwk(key: RsaCoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    return {
        kty: 'RSA',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'RS256',
        n: key['-1'].toString('base64url'),
        e: key['-2'].toString('base64url')
    };
}

export function coseToJwk(key: CoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml#key-type

    if (isEcCoseKey(key)) {
        return ecCoseToJwk(key);
    }

    if (isRsaCoseKey(key)) {
        return rsaCoseToJwk(key);
    }

    throw new Error('Unexpected key type ' + key['1']);
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

export async function verify(jwk: JsonWebKey, signature: Buffer, signedData: Buffer): Promise<boolean> {
    const importAlgorithm = getImportAlgorithm(jwk);
    const publicKey = await webcrypto.subtle.importKey('jwk', jwk, importAlgorithm, true, ['verify']);

    const verifyAlgorithm = getVerifyAlgorithm(jwk);
    return webcrypto.subtle.verify(verifyAlgorithm, publicKey, signature, signedData);
}

export function parseSignUpBody(body: string): SignUpBody {
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
            id: passkey.id,
            clientData: passkey.clientData,
            attestationObject,
            transports: passkey.transports
        }
    };
}

export function parseSignInBody(body: string): SignInBody {
    const parameters = new URLSearchParams(body);
    const passkeyJSON = parameters.get('passkey');
    assert(passkeyJSON !== null);
    const passkey = JSON.parse(passkeyJSON);

    return {
        id: passkey.id,
        clientDataJSON: passkey.clientDataJSON,
        signature: Buffer.from(passkey.signature, 'base64'),
        userHandle: Buffer.from(passkey.userHandle, 'base64'),
        authenticatorData: Buffer.from(passkey.authenticatorData, 'base64')
    };
}
