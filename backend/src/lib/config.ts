import { Buffer } from 'node:buffer';
import { sha256 } from './util.js';

const RUNNING_IN_AWS = !!process.env['AWS_REGION'];

const RP_ID = process.env['RP_ID'] ?? 'localhost';

export const PORT = 8080;

export const RP_ID_HASH = await sha256(Buffer.from(RP_ID, 'utf8'));

export const ALLOWED_ORIGINS = RUNNING_IN_AWS ? [`https://${RP_ID}`] : [`http://${RP_ID}:${PORT}`];

export const SESSION_COOKIE_NAME = 'SESSIONID';
