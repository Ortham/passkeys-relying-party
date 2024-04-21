import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { ALLOWED_ORIGINS } from './config.js';
import { isBitFlagSet } from './util.js';
import { CoseKey, mapToCoseKey } from './cose.js';
import { parseCBOR } from './cbor.js';

const FLAG_USER_PRESENT = 0b0001;
export const FLAG_USER_VERIFIED = 0b0100;
export const FLAG_BACKUP_ELIGIBILITY = 0b1000;
export const FLAG_BACKUP_STATE = 0b0001_0000;
const FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED = 0b0100_0000;
const FLAG_EXTENSION_DATA_INCLUDED = 0b1000_0000;

export interface ClientData {
    type: string;
    challenge: string;
    origin: string;
    topOrigin: unknown;
}

export interface AuthData {
    rpIdHash: Buffer;
    flags: number;
    signCount: number;
    aaguid: Buffer | undefined;
    credentialIdLength: number | undefined;
    credentialId: Buffer | undefined;
    credentialPublicKey: unknown;
    extensions: unknown;
}

export function assertIsClientData(
    value: unknown,
): asserts value is ClientData {
    assert.strictEqual(typeof value, 'object', 'clientData is not an object');
    assert(value !== null, 'clientData is null');

    const clientData = value as ClientData;

    assert.strictEqual(
        typeof clientData.type,
        'string',
        'clientData.type is not a string',
    );
    assert.strictEqual(
        typeof clientData.challenge,
        'string',
        'clientData.challenge is not a string',
    );
    assert.strictEqual(
        typeof clientData.origin,
        'string',
        'clientData.origin is not a string',
    );
}

export function validateClientData(
    clientData: ClientData,
    expectedType: string,
    expectedChallenge: Buffer,
) {
    assert.strictEqual(
        clientData.type,
        expectedType,
        "The client data's type is not expected",
    );

    // For some reason assert.strictEqual(clientData.challenge, expectedChallenge.toString('base64url')) fails when run in AWS Lambda, with the expected value logged being a byte array rather than the expected base64url string, it's like there's an invalid optimisation applied.
    assert(
        Buffer.from(clientData.challenge, 'base64url').equals(
            expectedChallenge,
        ),
        'The given challenge is not expected',
    );

    assert(
        ALLOWED_ORIGINS.includes(clientData.origin),
        `Origin ${clientData.origin} is not allowed`,
    );
    assert.strictEqual(
        clientData.topOrigin,
        undefined,
        'A top origin is present',
    );
}

function validateFlags(flags: number) {
    assert(
        isBitFlagSet(flags, FLAG_USER_PRESENT),
        'User Present bit is not set',
    );

    if (!isBitFlagSet(flags, FLAG_BACKUP_ELIGIBILITY)) {
        assert(
            !isBitFlagSet(flags, FLAG_BACKUP_STATE),
            'Backup State bit is set but Backup Eligible bit is not set',
        );
    }
}

export function parseAuthData(authData: Buffer): AuthData {
    // https://w3c.github.io/webauthn/#sctn-attested-credential-data

    const rpIdHash = authData.subarray(0, 32);
    const flags = authData.readUint8(32);
    const signCount = authData.readUint32BE(33);

    validateFlags(flags);

    const hasCredentialData = isBitFlagSet(
        flags,
        FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED,
    );
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
        const remaining = parseCBOR(authData.subarray(55 + credentialIdLength));

        if (hasExtensionData) {
            assert.strictEqual(
                remaining.length,
                2,
                'The AuthData structure has an unexpected number of fields',
            );

            assert(remaining[0] instanceof Map);
            credentialPublicKey = mapToCoseKey(remaining[0]);
            extensions = remaining[1];
        } else {
            assert.strictEqual(
                remaining.length,
                1,
                'The AuthData structure has an unexpected number of fields',
            );

            assert(remaining[0] instanceof Map);
            credentialPublicKey = mapToCoseKey(remaining[0]);
        }
    } else if (hasExtensionData) {
        const remaining = parseCBOR(authData.subarray(37));

        assert.strictEqual(
            remaining.length,
            1,
            'The AuthData structure has an unexpected number of fields',
        );

        extensions = remaining[0];
    } else {
        assert.strictEqual(
            authData.length,
            37,
            'The AuthData buffer length is unexpected',
        );
    }

    return {
        rpIdHash,
        flags,
        signCount,
        aaguid,
        credentialIdLength,
        credentialId,
        credentialPublicKey,
        extensions,
    };
}

export function validateAuthData(
    authData: AuthData,
    expectedRpIdHash: ArrayBuffer,
    requireCredentialData: boolean,
) {
    assert(
        authData.rpIdHash.equals(Buffer.from(expectedRpIdHash)),
        'The given RP ID hash is unexpected',
    );

    assert(
        isBitFlagSet(authData.flags, FLAG_USER_VERIFIED),
        'User Verified bit is not set',
    );

    if (requireCredentialData) {
        assert(
            isBitFlagSet(
                authData.flags,
                FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED,
            ),
            'No attested credential data included',
        );

        assert(
            authData.credentialIdLength !== undefined,
            'The credential ID is missing in the given AuthData',
        );
        assert(
            authData.credentialIdLength <= 1023,
            'Credential ID is greater than 1023 bytes long',
        );
    }
}
