import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { isValidSessionId, createSession, createChallenge, createNewUserId, handleSignUp, handleSignIn, logout, getProfile } from './service.js';

async function serveFile(res, filePath, contentType) {
    const file = await readFile('./public/' + filePath);

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(file);
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

    if (value === undefined || !isValidSessionId(value)) {
        value = createSession();
        res.setHeader('Set-Cookie', `${SESSION_COOKIE_NAME}=${value}; HttpOnly; SameSite=Strict`)
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
    const challenge = createChallenge(sessionId);

    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({ challenge }));
}

function serveNewUserId(res) {
    const id = createNewUserId();

    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({ id }));
}

function handleLogout(res, sessionId) {
    logout(sessionId);

    res.writeHead(302, { 'Location': '/' });
    res.end();
}

function handleGetProfile(res, sessionId) {
    const profile = getProfile(sessionId);

    // res.writeHead(200, {'Content-Type': 'application/json'});
    // res.end(JSON.stringify(profile));

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Username: ${profile.username}</p><p>Display name: ${profile.displayName}</p></body></html>`);
}

async function handleSignUpSubmit(req, res, sessionId) {
    // https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
    const bodyBuffer = await readBody(req);

    await handleSignUp(bodyBuffer, sessionId);

    res.writeHead(302, { 'Location': '/' });
    res.end();
}


async function handleSignInSubmit(req, res, sessionId) {
    // https://w3c.github.io/webauthn/#sctn-verifying-assertion
    const bodyBuffer = await readBody(req);

    const isValid = await handleSignIn(bodyBuffer, sessionId);

    if (isValid) {
        res.writeHead(302, { 'Location': '/' });
        res.end();
    } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Authentication failed!</p></body></html>`);
    }
}

export async function requestListener(req, res) {
    const HTML = 'text/html';
    const CSS = 'text/css';
    const JAVASCRIPT = 'text/javascript';

    const sessionId = setSessionCookie(req, res);

    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === 'GET') {
        if (url.pathname === '/') {
            await serveFile(res, 'index.html', HTML);
        } else if (url.pathname === '/signUp') {
            await serveFile(res, 'signUp.html', HTML);
        } else if (url.pathname === '/signIn') {
            await serveFile(res, 'signIn.html', HTML);
        } else if (url.pathname === '/style.css') {
            await serveFile(res, 'style.css', CSS);
        } else if (url.pathname === '/browser.js') {
            await serveFile(res, 'browser.js', JAVASCRIPT);
        } else if (url.pathname === '/challenge') {
            serveChallenge(res, sessionId);
        } else if (url.pathname === '/newUserId') {
            serveNewUserId(res);
        } else if (url.pathname === '/logout') {
            handleLogout(res, sessionId);
        } else if (url.pathname === '/profile') {
            handleGetProfile(res, sessionId);
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
}
