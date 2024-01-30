import { webcrypto } from 'node:crypto';

export function sha256(buffer: Buffer) {
    return webcrypto.subtle.digest('SHA-256', buffer);
}

export function isBitFlagSet(flags: number, flag: number) {
    return (flags & flag) === flag;
}
