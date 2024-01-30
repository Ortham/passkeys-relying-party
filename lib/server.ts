import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { isValidSessionId, createSession, createChallenge, createNewUserId, handleSignUp, handleSignIn, logout, getProfile } from './service.js';
import { IncomingMessage, ServerResponse } from 'node:http';
import assert from 'node:assert';

const SESSION_COOKIE_NAME = 'SESSIONID';

async function serveFile(res: ServerResponse, filePath: string, contentType: string) {
    const file = await readFile('./public/' + filePath);

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(file);
}

function getCookies(req: IncomingMessage) {
    if (req.headers.cookie) {
        const pairs: [string, string][] = req.headers.cookie.split('; ').map(pair => {
            const index = pair.indexOf('=');
            assert(index > 0);
            const key = pair.substring(0, index);
            const value = pair.substring(index + 1);
            return [key, value];
        });
        return new Map(pairs);
    }

    return new Map();
}

async function setSessionCookie(req: IncomingMessage, res: ServerResponse) {

    const cookies = getCookies(req);

    let value = cookies.get(SESSION_COOKIE_NAME);
    const isValid = await isValidSessionId(value);

    if (!isValid) {
        value = await createSession();
        res.setHeader('Set-Cookie', `${SESSION_COOKIE_NAME}=${value}; HttpOnly; SameSite=Strict; Secure`)
    }

    return value;
}

function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
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

async function serveChallenge(res: ServerResponse, sessionId: string) {
    const challenge = await createChallenge(sessionId);

    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({ challenge }));
}

function serveNewUserId(res: ServerResponse) {
    const id = createNewUserId();

    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({ id }));
}

async function handleLogout(res: ServerResponse, sessionId: string) {
    await logout(sessionId);

    res.writeHead(302, {
        'Location': '/',
        'Set-Cookie': `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Secure; Max-Age=0`
    });
    res.end();
}

async function handleGetProfile(res: ServerResponse, sessionId: string) {
    const profile = await getProfile(sessionId);

    if (profile) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Username: ${profile.username}</p><p>Display name: ${profile.displayName}</p></body></html>`);
    } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>You are not logged in!</p></body></html>`);
    }
}

async function handleSignUpSubmit(req: IncomingMessage, res: ServerResponse, sessionId: string) {
    // https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
    const body = await readBody(req);

    await handleSignUp(body, sessionId);

    res.writeHead(302, { 'Location': '/' });
    res.end();
}


async function handleSignInSubmit(req: IncomingMessage, res: ServerResponse, sessionId: string) {
    // https://w3c.github.io/webauthn/#sctn-verifying-assertion
    const body = await readBody(req);

    const isValid = await handleSignIn(body, sessionId);

    if (isValid) {
        res.writeHead(302, { 'Location': '/' });
        res.end();
    } else {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Authentication failed!</p></body></html>`);
    }
}

export async function requestListener(req: IncomingMessage, res: ServerResponse) {
    const HTML = 'text/html';
    const CSS = 'text/css';
    const JAVASCRIPT = 'text/javascript';

    assert(req.url);

    const sessionId = await setSessionCookie(req, res);

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
            await serveChallenge(res, sessionId);
        } else if (url.pathname === '/newUserId') {
            serveNewUserId(res);
        } else if (url.pathname === '/logout') {
            await handleLogout(res, sessionId);
        } else if (url.pathname === '/profile') {
            await handleGetProfile(res, sessionId);
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
