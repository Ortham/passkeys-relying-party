import { Buffer } from 'node:buffer';
import { readFile } from 'node:fs/promises';
import { IncomingMessage, ServerResponse } from 'node:http';
import assert, { AssertionError } from 'node:assert';
import {
    createChallenge,
    getOrCreateSession,
    getProfile,
    getSessionId,
    logout,
} from './session.js';
import { createUser } from '../handlers/createUser.js';
import { handleSignIn } from '../handlers/signIn.js';
import { deleteUser } from '../handlers/deleteUser.js';
import { getPasskeys } from '../handlers/getPasskeys.js';
import { createPasskey } from '../handlers/createPasskey.js';
import { deletePasskey } from '../handlers/deletePasskey.js';
import { database } from './database.js';
import { getSession } from '../handlers/getSession.js';

async function serveFile(
    res: ServerResponse,
    filePath: string,
    contentType: string,
) {
    const file = await readFile('../frontend/public/' + filePath);

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(file);
}

async function setSessionCookie(req: IncomingMessage, res: ServerResponse) {
    const { sessionId, responseHeaders } = await getOrCreateSession(
        req.headers,
    );

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
        req.on('data', (chunk: Buffer) => {
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

async function serveChallenge(req: IncomingMessage, res: ServerResponse) {
    const sessionId = await setSessionCookie(req, res);
    const challenge = await createChallenge(sessionId);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ challenge }));
}

async function handleLogout(res: ServerResponse, sessionId: string) {
    const responseHeaders = await logout(sessionId);

    res.writeHead(204, responseHeaders);
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

async function handleGetPasskeys(res: ServerResponse, sessionId: string) {
    const passkeys = await getPasskeys(sessionId);

    if (passkeys) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(passkeys));
    } else {
        res.writeHead(401);
        res.end();
    }
}

async function handleGetSession(res: ServerResponse, sessionId: string) {
    const session = await getSession(sessionId);

    if (session) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(session));
    } else {
        res.writeHead(404);
        res.end();
    }
}

async function handleSignUpSubmit(
    req: IncomingMessage,
    res: ServerResponse,
    sessionId: string,
) {
    // https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
    const body = await readBody(req);

    await createUser(body, sessionId);

    res.writeHead(204);
    res.end();
}

async function handleSignInSubmit(
    req: IncomingMessage,
    res: ServerResponse,
    sessionId: string,
) {
    // https://w3c.github.io/webauthn/#sctn-verifying-assertion
    const body = await readBody(req);

    const isValid = await handleSignIn(body, sessionId);

    if (isValid) {
        res.writeHead(204);
        res.end();
    } else {
        res.writeHead(400);
        res.end();
    }
}

async function handleCreatePasskey(
    req: IncomingMessage,
    res: ServerResponse,
    sessionId: string,
) {
    const body = await readBody(req);

    const user = await database.getUserBySessionId(sessionId);
    assert(user !== undefined, 'No user found for the given session ID');

    await createPasskey(body, sessionId, user);

    res.writeHead(204);
    res.end();
}

async function handleDeleteUser(res: ServerResponse, sessionId: string) {
    const responseHeaders = await deleteUser(sessionId);

    res.writeHead(204, responseHeaders);
    res.end();
}

async function handleDeletePasskey(
    res: ServerResponse,
    sessionId: string,
    passkeyId: string,
) {
    await deletePasskey(sessionId, passkeyId);

    res.writeHead(204);
    res.end();
}

export async function requestListener(
    req: IncomingMessage,
    res: ServerResponse,
) {
    const HTML = 'text/html';
    const CSS = 'text/css';
    const JAVASCRIPT = 'text/javascript';

    try {
        assert(req.url, 'The request has no URL');

        const sessionId = getSessionId(req.headers);

        const url = new URL(req.url, `http://${req.headers.host}`);
        if (req.method === 'GET') {
            if (url.pathname === '/') {
                await serveFile(res, 'index.html', HTML);
            } else if (url.pathname === '/account.html') {
                await serveFile(res, 'account.html', HTML);
            } else if (url.pathname === '/signUp.html') {
                await serveFile(res, 'signUp.html', HTML);
            } else if (url.pathname === '/style.css') {
                await serveFile(res, 'style.css', CSS);
            } else if (url.pathname === '/browser.js') {
                await serveFile(res, 'browser.js', JAVASCRIPT);
            } else if (url.pathname === '/api/challenge') {
                await serveChallenge(req, res);
            } else if (url.pathname === '/api/logout') {
                assert(sessionId);
                await handleLogout(res, sessionId);
            } else if (url.pathname === '/api/profile') {
                assert(sessionId);
                await handleGetProfile(res, sessionId);
            } else if (url.pathname === '/api/passkeys') {
                assert(sessionId);
                await handleGetPasskeys(res, sessionId);
            } else if (url.pathname === '/api/session') {
                assert(sessionId);
                await handleGetSession(res, sessionId);
            } else {
                res.writeHead(404);
                res.end();
            }
        } else if (req.method === 'POST') {
            if (url.pathname === '/api/user') {
                assert(sessionId);
                await handleSignUpSubmit(req, res, sessionId);
            } else if (url.pathname === '/api/signIn') {
                assert(sessionId);
                await handleSignInSubmit(req, res, sessionId);
            } else if (url.pathname === '/api/passkeys') {
                assert(sessionId);
                await handleCreatePasskey(req, res, sessionId);
            } else {
                res.writeHead(404);
                res.end();
            }
        } else if (req.method === 'DELETE') {
            if (url.pathname === '/api/user') {
                assert(sessionId);
                await handleDeleteUser(res, sessionId);
            } else if (url.pathname.startsWith('/api/passkeys/')) {
                const passkeyId = url.pathname.split('/').at(-1);
                assert(
                    passkeyId !== undefined && passkeyId.length > 0,
                    'The request path has no passkey ID',
                );
                assert(sessionId);
                await handleDeletePasskey(res, sessionId, passkeyId);
            } else {
                res.writeHead(404);
                res.end();
            }
        } else {
            res.writeHead(405);
            res.end();
        }
    } catch (err) {
        console.error('Caught thrown error', err);
        if (err instanceof AssertionError) {
            res.writeHead(400);
            res.end();
        } else {
            res.writeHead(500);
            res.end();
        }
    }
}
