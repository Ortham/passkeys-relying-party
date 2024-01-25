const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const cbor = require('cbor');

const PORT = 8080;

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

function parseAuthData(authData) {
    // https://w3c.github.io/webauthn/#sctn-attested-credential-data
    const rpIdHash = authData.subarray(0, 32);
    const flags = authData.readUint8(32);
    const counter = authData.readUint32BE(33);
    const aaGuid = authData.subarray(37, 53);
    const credentialIdLength = authData.readUint16BE(53);
    const credentialId = authData.subarray(55, 55 + credentialIdLength);
    const credential = cbor.decodeFirstSync(authData.subarray(55 + credentialIdLength));

    return { rpIdHash, flags, counter, aaGuid, credentialIdLength, credentialId, credential };
}

function decodeAttestationObject(attestationObject) {
    // https://w3c.github.io/webauthn/#attestation-object
    const { fmt, attStmt, authData } = cbor.decodeFirstSync(attestationObject);

    assert.strictEqual(fmt, 'none');
    assert.strictEqual(Object.keys(attStmt).length, 0);

    return parseAuthData(authData);
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
            attestationObject
        }
    };
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


    // TODO: Validate rpIdHash, validate user present flag is set, validate BE and BS flags, validate algorithm is an expected value, a lot more.

    const jwk = coseToJwk(body.passkey.attestationObject.credential);
    const algorithm = getAlgorithm(jwk);

    const publicKey = await crypto.subtle.importKey('jwk', jwk, algorithm, true, ['verify']);

    const user = {
        id: body.userId,
        name: body.username,
        displayName: body.displayName,
        passkey: {
            id: body.passkey.id,
            publicKey,
            algorithm
            // TODO: Store other fields necessary for validation. <https://w3c.github.io/webauthn/#credential-record>
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

    // TODO: Validate rpIdHash, validate user present flag is set, validate BE and BS flags, validate algorithm is an expected value, a lot more.

    const hash = await crypto.subtle.digest('SHA-256', Buffer.from(body.clientDataJSON, 'utf-8'));
    const signedData = Buffer.concat([body.authenticatorData, Buffer.from(hash)]);

    const isValid = await crypto.subtle.verify(user.passkey.algorithm, user.passkey.publicKey, body.signature, signedData);

    if (isValid) {
        console.log('Authentication successful!');

        // TODO: Update session to indicate that the user is authenticated.
        // TODO: Update the stored passkey data as necessary.

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
