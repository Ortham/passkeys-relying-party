import { Buffer } from 'node:buffer';
import { env } from 'node:process';
import { sha256 } from './util.js';

const RUNNING_IN_AWS = !!env['AWS_REGION'];

const RP_ID = env['RP_ID'] ?? 'localhost';

export const PORT = 8080;

export const RP_ID_HASH = sha256(Buffer.from(RP_ID, 'utf8'));

export const ALLOWED_ORIGINS = RUNNING_IN_AWS
    ? [`https://${RP_ID}`]
    : [`http://${RP_ID}:${PORT}`];

export const SESSION_COOKIE_NAME = 'SESSIONID';
