
import { SESSION_COOKIE_NAME } from './config.js';
import { database } from './database.js';
import { getCookies, getRandomBytes } from './util.js';

function isValidSessionId(sessionId: string | undefined) {
    if (sessionId === undefined) {
        return false;
    }

    return database.sessionExists(sessionId);
}

async function createSession() {
    const sessionId = getRandomBytes(16).toString('base64url');

    await database.insertSession(sessionId);

    return sessionId;
}

export function getSessionId(requestHeaders: Record<string, string | string[] | undefined>) {
    return getCookies(requestHeaders).get(SESSION_COOKIE_NAME);
}

export async function getOrCreateSession(requestHeaders: Record<string, string | string[] | undefined>) {
    let sessionId = getSessionId(requestHeaders);
    const isValid = await isValidSessionId(sessionId);

    let responseHeaders: Record<string, string> | undefined;
    if (!isValid) {
        console.warn('Session ID', sessionId, 'is not valid, creating new session');
        sessionId = await createSession();
        responseHeaders = {
            'Set-Cookie': `${SESSION_COOKIE_NAME}=${sessionId}; HttpOnly; SameSite=Strict; Secure`
        };
    }

    return {
        sessionId: sessionId!,
        responseHeaders
    };
}

export async function createChallenge(sessionId: string) {
    const challenge = getRandomBytes(16);

    await database.updateSessionChallenge(sessionId, challenge);

    return challenge.toString('base64url');
}

export async function logout(sessionId: string) {
    await database.deleteSession(sessionId);

    return {
        'Set-Cookie': `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Secure; Max-Age=0`
    };
}

export async function getProfile(sessionId: string) {
    const user = await database.getUserBySessionId(sessionId);
    if (!user) {
        return undefined;
    }

    return {
        userHandle: user.userHandle.toString('base64url'),
        username: user.name,
        displayName: user.displayName
    };
}
