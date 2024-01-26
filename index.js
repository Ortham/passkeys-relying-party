const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const cbor = require('cbor');

const PORT = 8080;

const FLAG_USER_PRESENT = 0b0001;
const FLAG_USER_VERIFIED = 0b0100;
const FLAG_BACKUP_ELIGIBILITY = 0b1000;
const FLAG_BACKUP_STATE = 0b0001_0000;
const FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED = 0b0100_0000;
const FLAG_EXTENSION_DATA_INCLUDED = 0b1000_0000;

class Database {
    constructor() {
        this.users = new Map();
        this.challenges = new Map();
    }

    insertUser(user) {
        this.users.set(user.id.toString('base64'), user);
    }

    getUser(userId) {
        return this.users.get(userId.toString('base64'));
    }

    insertChallenge(sessionId, challenge) {
        this.challenges.set(sessionId, challenge);
    }

    getChallenge(sessionId) {
        return this.challenges.get(sessionId);
    }

    countUsersByCredentialId(credentialId) {
        const passkeyId = credentialId.toString('base64url');
        let count = 0;

        for (const [_id, user] of this.users) {
            if (user.passkey.id === passkeyId) {
                count += 1;
            }
        }

        return count;
    }

    updatePasskeyState(userId, signCount, backupState) {
        const user = this.users.get(userId.toString('base64'));

        user.passkey.signCount = signCount;
        user.passkey.backupState = backupState;
    }
};

const database = new Database();

function serveFile(res, filePath, contentType) {
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(fs.readFileSync('./public/' + filePath));
}

function getCookies(req) {
    if (req.headers.cookie) {
        return new Map(req.headers.cookie.split('; ').map(pair => pair.split('=')));
    }

    return new Map();
}

function setSessionCookie(req, res) {
    const SESSION_COOKIE_NAME = 'SESSIONID';

    const cookies = getCookies(req);

    let value = cookies.get(SESSION_COOKIE_NAME);

    if (value === undefined) {
        value = crypto.randomBytes(16).toString('base64');
        res.setHeader('Set-Cookie', [`${SESSION_COOKIE_NAME}=${value}`, 'HttpOnly', 'SameSite=Strict'])
    }

    return value;
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', chunk => {
            chunks.push(chunk);
        });
        req.on('end', () => {
            const body = Buffer.concat(chunks).toString();
            console.log('Received request body:', body);

            resolve(body);
        });
        req.on('error', reject);
    });
}

function serveChallenge(res, sessionId) {
    const challenge = crypto.randomBytes(16);

    database.insertChallenge(sessionId, challenge);

    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({
        challenge: challenge.toString('base64url')
    }));
}

function serveNewUserId(res) {
    // TODO: Come up with a better way of handling user ID generation.
    // Would be better to insert this into the DB now in case of collisions.
    const userId = crypto.randomBytes(16).toString('base64url');

    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({
        id: userId
    }));
}

function validateClientData(clientData, sessionId, expectedType) {
    const allowedOrigins = [`http://localhost:${PORT}`];

    const expectedChallenge = database.getChallenge(sessionId);

    assert.strictEqual(clientData.type, expectedType);
    assert.strictEqual(clientData.challenge, expectedChallenge.toString('base64url'));
    assert(allowedOrigins.includes(clientData.origin), `Origin ${clientData.origin} is not allowed`);
    assert.strictEqual(clientData.topOrigin, undefined);
}

function isBitFlagSet(flags, flag) {
    return (flags & flag) === flag;
}

function validateFlags(flags) {
    assert(isBitFlagSet(flags, FLAG_USER_PRESENT), 'User Present bit is not set');
    assert(isBitFlagSet(flags, FLAG_USER_VERIFIED), 'User Verified bit is not set');

    if (!isBitFlagSet(flags, FLAG_BACKUP_ELIGIBILITY)) {
        assert(!isBitFlagSet(flags, FLAG_BACKUP_STATE), 'Backup State bit is set but Backup Eligible bit is not set');
    }
}

function parseAuthData(authData, requireCredentialData) {
    // https://w3c.github.io/webauthn/#sctn-attested-credential-data

    const rpIdHash = authData.subarray(0, 32);
    const flags = authData.readUint8(32);
    const signCount = authData.readUint32BE(33);

    validateFlags(flags);

    const hasCredentialData = isBitFlagSet(flags, FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED);
    const hasExtensionData = isBitFlagSet(flags, FLAG_EXTENSION_DATA_INCLUDED);

    if (requireCredentialData) {
        assert(hasCredentialData, 'No attested credential data included');
    }

    let aaguid;
    let credentialIdLength;
    let credentialId;
    let credentialPublicKey;
    let extensions = new Map();
    if (hasCredentialData) {
        // Attested credential data fields.
        aaguid = authData.subarray(37, 53);
        credentialIdLength = authData.readUint16BE(53);
        credentialId = authData.subarray(55, 55 + credentialIdLength);

        // Next field is the credential public key, but it may be followed by an extensions map.
        const remaining = cbor.decodeAllSync(authData.subarray(55 + credentialIdLength));

        console.log('Flags are', flags, 'remaining is', remaining);

        if (hasExtensionData) {
            assert.strictEqual(remaining.length, 2);

            credentialPublicKey = remaining[0];
            extensions = remaining[1];
        } else {
            assert.strictEqual(remaining.length, 1);

            credentialPublicKey = remaining[0];
        }
    } else if (hasExtensionData) {
        const remaining = cbor.decodeAllSync(authData.subarray(37));

        assert.strictEqual(remaining.length, 1);

        extensions = remaining[0];
    } else {
        assert(authData.length, 37);
    }

    return { rpIdHash, flags, signCount, aaguid, credentialIdLength, credentialId, credentialPublicKey, extensions };
}

function decodeAttestationObject(attestationObject) {
    // https://w3c.github.io/webauthn/#attestation-object
    const { fmt, attStmt, authData } = cbor.decodeFirstSync(attestationObject);

    assert.strictEqual(fmt, 'none');
    assert.strictEqual(Object.keys(attStmt).length, 0);

    return parseAuthData(authData, true);
}

function parseSignUpBody(body) {
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

async function validateRpIdHash(rpIdHash) {
    const RP_ID = Buffer.from('localhost', 'utf-8');
    const expectedRpIdHash = await crypto.subtle.digest('SHA-256', RP_ID);

    assert.strictEqual(rpIdHash.toString('hex'), Buffer.from(expectedRpIdHash).toString('hex'));
}

function ecCodeToJwk(credential) {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518
    const WEBAUTHN_ALG_ES256 = -7;

    const alg = credential.get(3);
    assert.strictEqual(alg, WEBAUTHN_ALG_ES256);

    const COSE_EC_P256 = 1;
    const crv = credential.get(-1);
    assert.strictEqual(crv, COSE_EC_P256);

    return {
        kty: 'EC',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'ES256',
        crv: 'P-256',
        x: credential.get(-2).toString('base64url'),
        y: credential.get(-3).toString('base64url')
    };
}

function rsaCoseToJwk(credential) {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518
    const WEBAUTHN_ALG_RS256 = -257;

    const alg = credential.get(3);
    assert.strictEqual(alg, WEBAUTHN_ALG_RS256);

    return {
        kty: 'RSA',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'RS256',
        n: credential.get(-1).toString('base64url'),
        e: credential.get(-2).toString('base64url')
    };
}

function coseToJwk(credential) {
    // https://www.iana.org/assignments/cose/cose.xhtml#key-type
    const COSE_KEY_TYPE_EC2 = 2;
    const COSE_KEY_TYPE_RSA = 3;

    const kty = credential.get(1);

    if (kty === COSE_KEY_TYPE_EC2) {
        return ecCodeToJwk(credential);
    } else if (kty === COSE_KEY_TYPE_RSA) {
        return rsaCoseToJwk(credential);
    } else {
        throw new Error('Unexpected key type ' + kty);
    }
}

function getAlgorithm(jwk) {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', namedCurve: 'P-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

async function handleSignUpSubmit(req, res, sessionId) {
    // https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
    const bodyBuffer = await readBody(req);
    const body = parseSignUpBody(bodyBuffer);
    console.log('Request body is', body);

    validateClientData(body.passkey.clientData, sessionId, 'webauthn.create');

    await validateRpIdHash(body.passkey.attestationObject.rpIdHash);

    // Don't care about backup eligibility or backup state beyond validation.
    // Don't care about client extensions.

    assert(body.passkey.attestationObject.credentialIdLength <= 1023, 'Credential ID is greater than 1023 bytes long');

    const matchingCredentialIdCount = database.countUsersByCredentialId(body.passkey.attestationObject.credentialId);
    assert.strictEqual(matchingCredentialIdCount, 0);

    const jwk = coseToJwk(body.passkey.attestationObject.credentialPublicKey);
    const algorithm = getAlgorithm(jwk);

    const publicKey = await crypto.subtle.importKey('jwk', jwk, algorithm, true, ['verify']);

    const user = {
        id: body.userId,
        name: body.username,
        displayName: body.displayName,
        passkey: {
            id: body.passkey.id,
            publicKey,
            algorithm,
            signCount: body.passkey.attestationObject.signCount,
            uvInitialized: isBitFlagSet(body.passkey.attestationObject.flags, FLAG_USER_VERIFIED),
            transports: body.passkey.transports,
            backupEligible: isBitFlagSet(body.passkey.attestationObject.flags, FLAG_BACKUP_ELIGIBILITY),
            backupState: isBitFlagSet(body.passkey.attestationObject.flags, FLAG_BACKUP_STATE)
        }
    };

    database.insertUser(user);
    console.log('Stored user', user);

    res.writeHead(302, { 'Location': '/' });
    res.end();
}

function parseSignInBody(body) {
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

async function handleSignInSubmit(req, res, sessionId) {
    // https://w3c.github.io/webauthn/#sctn-verifying-assertion
    const bodyBuffer = await readBody(req);
    const body = parseSignInBody(bodyBuffer);
    console.log('Request body is', body);

    const user = database.getUser(body.userHandle);
    console.log('Retrieved user data', user);

    assert.strictEqual(body.id, user.passkey.id);

    const clientData = JSON.parse(body.clientDataJSON);

    validateClientData(clientData, sessionId, 'webauthn.get');

    const authData = parseAuthData(body.authenticatorData, false);

    await validateRpIdHash(authData.rpIdHash);

    validateFlags(authData.flags);

    const isBackupEligible = isBitFlagSet(authData.flags, FLAG_BACKUP_ELIGIBILITY);
    assert.strictEqual(isBackupEligible, user.passkey.backupEligible, "Backup Eligiblity state has changed");

    // Don't care about backup eligibility or state beyond basic validation.
    // Don't care about client extensions.

    const hash = await crypto.subtle.digest('SHA-256', Buffer.from(body.clientDataJSON, 'utf-8'));
    const signedData = Buffer.concat([body.authenticatorData, Buffer.from(hash)]);

    const isValid = await crypto.subtle.verify(user.passkey.algorithm, user.passkey.publicKey, body.signature, signedData);

    if (isValid) {
        console.log('Authentication successful!');

        if (authData.signCount < user.passkey.signCount) {
            console.warn('The stored sign count is greater than the given sign count, the authenticator may be cloned');
        }

        // No need to update uvInitialised as it's required to be true initially.
        assert(user.passkey.uvInitialized);

        const isBackedUp = isBitFlagSet(authData.flags, FLAG_BACKUP_STATE);
        database.updatePasskeyState(body.userHandle, authData.signCount, isBackedUp);

        // TODO: Update session to indicate that the user is authenticated.

        res.writeHead(302, { 'Location': '/' });
        res.end();
    } else {
        console.error('Authentication failed!');

        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Authentication failed!</p></p></html>`);
    }
}

const server = http.createServer(async (req, res) => {
    const HTML = 'text/html';
    const CSS = 'text/css';
    const JAVASCRIPT = 'text/javascript';

    const sessionId = setSessionCookie(req, res);

    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === 'GET') {
        if (url.pathname === '/') {
            serveFile(res, 'index.html', HTML);
        } else if (url.pathname === '/signUp') {
            serveFile(res, 'signUp.html', HTML);
        } else if (url.pathname === '/signIn') {
            serveFile(res, 'signIn.html', HTML);
        } else if (url.pathname === '/style.css') {
            serveFile(res, 'style.css', CSS);
        } else if (url.pathname === '/browser.js') {
            serveFile(res, 'browser.js', JAVASCRIPT);
        } else if (url.pathname === '/challenge') {
            serveChallenge(res, sessionId);
        } else if (url.pathname === '/newUserId') {
            serveNewUserId(res);
        } else {
            res.writeHead(404);
            res.end();
        }
    } else if (req.method === 'POST') {
        if (url.pathname === '/signUp') {
            await handleSignUpSubmit(req, res, sessionId);
        } else if (url.pathname === '/signIn') {
            await handleSignInSubmit(req, res, sessionId);
        } else {
            res.writeHead(404);
            res.end();
        }
    } else {
        res.writeHead(405);
        res.end();
    }
});

server.listen(PORT);
console.log(`Listening on port ${PORT}`);
