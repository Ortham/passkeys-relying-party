import { webcrypto } from 'node:crypto';

export function sha256(buffer) {
    return webcrypto.subtle.digest('SHA-256', buffer);
}

export function isBitFlagSet(flags, flag) {
    return (flags & flag) === flag;
}
