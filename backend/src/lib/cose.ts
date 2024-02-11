import assert from "node:assert";
import { Buffer } from 'node:buffer';
import { DecodedValue } from "./cbor.js";

const COSE_ALG_ES256 = -7;
const COSE_ALG_EDDSA = -8;
const COSE_ALG_RS256 = -257;
const COSE_EC_P256 = 1;
const COSE_EC_ED25519 = 6;
const COSE_KEY_TYPE_EC2 = 2;
const COSE_KEY_TYPE_OKP = 1;
const COSE_KEY_TYPE_RSA = 3;

export interface CoseKey {
    '1': number;
    '3': number;

    [key: string]: unknown;
}

interface EcdsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_EC2;
    '3': typeof COSE_ALG_ES256;
    '-1': typeof COSE_EC_P256;
    '-2': Buffer;
    '-3': Buffer;
}

interface EddsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_OKP;
    '3': typeof COSE_ALG_EDDSA;
    '-1': typeof COSE_EC_ED25519;
    '-2': Buffer;
}

interface RsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_RSA;
    '3': typeof COSE_ALG_RS256;
    '-1': Buffer;
    '-2': Buffer;
}

function isEcdsaCoseKey(key: CoseKey): key is EcdsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_EC2
        && key['3'] === COSE_ALG_ES256
        && key['-1'] === COSE_EC_P256
        && Buffer.isBuffer(key['-2'])
        && Buffer.isBuffer(key['-3']);
}

function isEddsaCoseKey(key: CoseKey): key is EddsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_OKP
        && key['3'] === COSE_ALG_EDDSA
        && key['-1'] === COSE_EC_ED25519
        && Buffer.isBuffer(key['-2']);
}

function isRsaCoseKey(key: CoseKey): key is RsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_RSA
        && key['3'] === COSE_ALG_RS256
        && Buffer.isBuffer(key['-1'])
        && Buffer.isBuffer(key['-2']);
}

function ecdsaCoseToJwk(key: EcdsaCoseKey): JsonWebKey {
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

function eddsaCoseToJwk(key: EddsaCoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    return {
        kty: 'OKP',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'EdDSA',
        crv: 'Ed25519',
        x: key['-2'].toString('base64url')
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

    if (isEcdsaCoseKey(key)) {
        return ecdsaCoseToJwk(key);
    }

    if (isEddsaCoseKey(key)) {
        return eddsaCoseToJwk(key);
    }

    if (isRsaCoseKey(key)) {
        return rsaCoseToJwk(key);
    }

    throw new Error('Unexpected key type ' + key['1']);
}
