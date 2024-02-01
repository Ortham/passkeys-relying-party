import assert from 'node:assert';
import { webcrypto } from 'node:crypto';

export function getRandomBytes(count: number) {
    const array = new Uint8Array(count);
    webcrypto.getRandomValues(array);

    return Buffer.from(array.buffer);
}

export function sha256(buffer: Buffer) {
    return webcrypto.subtle.digest('SHA-256', buffer);
}

export function isBitFlagSet(flags: number, flag: number) {
    return (flags & flag) === flag;
}

export function getCookieHeader(requestHeaders: Record<string, string | string[] | undefined>): string | undefined {
    const stringHeaders: [string, string][] = [];
    for (const [key, value] of Object.entries(requestHeaders)) {
        if (Array.isArray(value)) {
            const entries: [string, string][] = value.map(v => [key, v]);
            stringHeaders.push(...entries);
        } else if (value !== undefined) {
            stringHeaders.push([key, value]);
        }
    }

    const headers = new Headers(stringHeaders);
    const cookie = headers.get('Cookie');

    return cookie === null ? undefined : cookie;
}

export function getCookies(requestHeaders: Record<string, string | string[] | undefined>): Map<string, string> {
    const cookieHeader = getCookieHeader(requestHeaders);
    if (cookieHeader) {
        const pairs: [string, string][] = cookieHeader.split('; ').map(pair => {
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
