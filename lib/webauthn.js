import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { decode, decodeMultiple } from 'cbor-x/decode';
import { PORT } from './config.js';
import { isBitFlagSet, sha256 } from './util.js';

const FLAG_USER_PRESENT = 0b0001;
export const FLAG_USER_VERIFIED = 0b0100;
export const FLAG_BACKUP_ELIGIBILITY = 0b1000;
export const FLAG_BACKUP_STATE = 0b0001_0000;
const FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED = 0b0100_0000;
const FLAG_EXTENSION_DATA_INCLUDED = 0b1000_0000;



export function validateClientData(clientData, expectedType, expectedChallenge) {
    const allowedOrigins = [`http://localhost:${PORT}`];

    assert.strictEqual(clientData.type, expectedType);
    assert.strictEqual(clientData.challenge, expectedChallenge.toString('base64url'));
    assert(allowedOrigins.includes(clientData.origin), `Origin ${clientData.origin} is not allowed`);
    assert.strictEqual(clientData.topOrigin, undefined);
}

function validateFlags(flags) {
    assert(isBitFlagSet(flags, FLAG_USER_PRESENT), 'User Present bit is not set');

    if (!isBitFlagSet(flags, FLAG_BACKUP_ELIGIBILITY)) {
        assert(!isBitFlagSet(flags, FLAG_BACKUP_STATE), 'Backup State bit is set but Backup Eligible bit is not set');
    }
}

export function parseAuthData(authData) {
    // https://w3c.github.io/webauthn/#sctn-attested-credential-data

    const rpIdHash = authData.subarray(0, 32);
    const flags = authData.readUint8(32);
    const signCount = authData.readUint32BE(33);

    validateFlags(flags);

    const hasCredentialData = isBitFlagSet(flags, FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED);
    const hasExtensionData = isBitFlagSet(flags, FLAG_EXTENSION_DATA_INCLUDED);

    let aaguid;
    let credentialIdLength;
    let credentialId;
    let credentialPublicKey;
    let extensions;
    if (hasCredentialData) {
        // Attested credential data fields.
        aaguid = authData.subarray(37, 53);
        credentialIdLength = authData.readUint16BE(53);
        credentialId = authData.subarray(55, 55 + credentialIdLength);

        // Next field is the credential public key, but it may be followed by an extensions map.
        const remaining = decodeMultiple(authData.subarray(55 + credentialIdLength));

        if (hasExtensionData) {
            assert.strictEqual(remaining.length, 2);

            credentialPublicKey = remaining[0];
            extensions = remaining[1];
        } else {
            assert.strictEqual(remaining.length, 1);

            credentialPublicKey = remaining[0];
        }
    } else if (hasExtensionData) {
        const remaining = decodeMultiple(authData.subarray(37));

        assert.strictEqual(remaining.length, 1);

        extensions = remaining[0];
    } else {
        assert.strictEqual(authData.length, 37);
    }

    return { rpIdHash, flags, signCount, aaguid, credentialIdLength, credentialId, credentialPublicKey, extensions };
}

function decodeAttestationObject(attestationObject) {
    // https://w3c.github.io/webauthn/#attestation-object
    const { fmt, attStmt, authData } = decode(attestationObject);

    return { fmt, attStmt, ...parseAuthData(authData) };
}

export async function validateAuthData(authData, expectedRpId, requireCredentialData) {
    const expectedRpIdHash = await sha256(expectedRpId);

    assert.strictEqual(authData.rpIdHash.toString('hex'), Buffer.from(expectedRpIdHash).toString('hex'));

    assert(isBitFlagSet(authData.flags, FLAG_USER_VERIFIED), 'User Verified bit is not set');

    if (requireCredentialData) {
        assert(isBitFlagSet(authData.flags, FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED), 'No attested credential data included');

        assert(authData.credentialIdLength <= 1023, 'Credential ID is greater than 1023 bytes long');
    }
}

export async function validateAttestationObject(attestationObject, expectedRpId) {
    assert.strictEqual(attestationObject.fmt, 'none');
    assert.strictEqual(Object.keys(attestationObject.attStmt).length, 0);

    await validateAuthData(attestationObject, expectedRpId, true);
}

export function parseSignUpBody(body) {
    const parameters = new URLSearchParams(body);
    const passkey = JSON.parse(parameters.get('passkey'));
    const attestationObject = decodeAttestationObject(Buffer.from(passkey.attestationObject, 'base64'));

    return {
        userId: Buffer.from(passkey.userId, 'base64url'),
        username: parameters.get('username'),
        displayName: parameters.get('displayName'),
        passkey: {
            id: passkey.id,
            clientData: passkey.clientData,
            attestationObject,
            transports: passkey.transports
        }
    };
}

function ecCodeToJwk(credential) {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518
    const WEBAUTHN_ALG_ES256 = -7;

    const alg = credential['3'];
    assert.strictEqual(alg, WEBAUTHN_ALG_ES256);

    const COSE_EC_P256 = 1;
    const crv = credential['-1'];
    assert.strictEqual(crv, COSE_EC_P256);

    return {
        kty: 'EC',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'ES256',
        crv: 'P-256',
        x: credential['-2'].toString('base64url'),
        y: credential['-3'].toString('base64url')
    };
}

function rsaCoseToJwk(credential) {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518
    const WEBAUTHN_ALG_RS256 = -257;

    const alg = credential['3'];
    assert.strictEqual(alg, WEBAUTHN_ALG_RS256);

    return {
        kty: 'RSA',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'RS256',
        n: credential['-1'].toString('base64url'),
        e: credential['-2'].toString('base64url')
    };
}

export function coseToJwk(credential) {
    // https://www.iana.org/assignments/cose/cose.xhtml#key-type
    const COSE_KEY_TYPE_EC2 = 2;
    const COSE_KEY_TYPE_RSA = 3;

    const kty = credential['1'];

    if (kty === COSE_KEY_TYPE_EC2) {
        return ecCodeToJwk(credential);
    } else if (kty === COSE_KEY_TYPE_RSA) {
        return rsaCoseToJwk(credential);
    } else {
        throw new Error('Unexpected key type ' + kty);
    }
}

export function getAlgorithm(jwk) {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', namedCurve: 'P-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

export function parseSignInBody(body) {
    const parameters = new URLSearchParams(body);
    const passkey = JSON.parse(parameters.get('passkey'));

    return {
        id: passkey.id,
        clientDataJSON: passkey.clientDataJSON,
        signature: Buffer.from(passkey.signature, 'base64'),
        userHandle: Buffer.from(passkey.userHandle, 'base64'),
        authenticatorData: Buffer.from(passkey.authenticatorData, 'base64')
    };
}
