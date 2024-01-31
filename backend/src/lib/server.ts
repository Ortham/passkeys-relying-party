import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { createChallenge, createNewUserId, handleSignUp, handleSignIn, logout, getProfile, getOrCreateSession } from './service.js';
import { IncomingMessage, ServerResponse } from 'node:http';
import assert from 'node:assert';

async function serveFile(res: ServerResponse, filePath: string, contentType: string) {
    const file = await readFile('../frontend/public/' + filePath);

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(file);
}

async function setSessionCookie(req: IncomingMessage, res: ServerResponse) {
    const { sessionId, responseHeaders } = await getOrCreateSession(req.headers);

    if (responseHeaders) {
        for (const [name, value] of Object.entries(responseHeaders)) {
            res.setHeader(name, value);
        }
    }

    return sessionId;
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
    const responseHeaders = await logout(sessionId);

    res.writeHead(302, {
        ...responseHeaders,
        'Location': '/'
    });
    res.end();
}

async function handleGetProfile(res: ServerResponse, sessionId: string) {
    const profile = await getProfile(sessionId);

    if (profile) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
    } else {
        res.writeHead(401);
        res.end();
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
        } else if (url.pathname === '/profile.html') {
            await serveFile(res, 'profile.html', HTML);
        } else if (url.pathname === '/signUp.html') {
            await serveFile(res, 'signUp.html', HTML);
        } else if (url.pathname === '/signIn.html') {
            await serveFile(res, 'signIn.html', HTML);
        } else if (url.pathname === '/style.css') {
            await serveFile(res, 'style.css', CSS);
        } else if (url.pathname === '/browser.js') {
            await serveFile(res, 'browser.js', JAVASCRIPT);
        } else if (url.pathname === '/api/challenge') {
            await serveChallenge(res, sessionId);
        } else if (url.pathname === '/api/newUserId') {
            serveNewUserId(res);
        } else if (url.pathname === '/api/logout') {
            await handleLogout(res, sessionId);
        } else if (url.pathname === '/api/profile') {
            await handleGetProfile(res, sessionId);
        } else {
            res.writeHead(404);
            res.end();
        }
    } else if (req.method === 'POST') {
        if (url.pathname === '/api/signUp') {
            await handleSignUpSubmit(req, res, sessionId);
        } else if (url.pathname === '/api/signIn') {
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
