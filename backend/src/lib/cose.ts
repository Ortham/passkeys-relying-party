import assert from "node:assert";
import { Buffer } from 'node:buffer';
import { DecodedValue } from "./cbor.js";

const WEBAUTHN_ALG_ES256 = -7;
const WEBAUTHN_ALG_RS256 = -257;
const COSE_EC_P256 = 1;
const COSE_KEY_TYPE_EC2 = 2;
const COSE_KEY_TYPE_RSA = 3;

export interface CoseKey {
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

export function mapToCoseKey(map: Map<DecodedValue, DecodedValue>): CoseKey {
    console.log('Decoded COSE key is', map);
    const publicKey = Object.fromEntries(map);

    assert(publicKey !== null, 'The public key is null');
    assert(typeof publicKey === 'object', 'The public key is not an object');
    assert('1' in publicKey, 'The public key\'s kty field is missing');
    assert('3' in publicKey, 'The public key\'s alg field is missing');

    return publicKey;
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
