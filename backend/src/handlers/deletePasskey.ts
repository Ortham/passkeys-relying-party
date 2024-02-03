import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId } from '../lib/session.js';
import { database } from '../lib/database.js';
import assert from 'node:assert';

export async function deletePasskey(sessionId: string, credentialIdString: string) {
    // First check that the current user owns the given credential, then remove it.
    const credentialId = Buffer.from(credentialIdString, 'base64url');

    const user = await database.getUserBySessionId(sessionId);
    assert(user !== undefined);

    assert(user.passkeys.size > 1);
    assert(user.passkeys.has(credentialId.toString('base64')));

    await database.deletePasskey(credentialId);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    const credentialId = event.pathParameters?.['credentialId'];
    assert(credentialId !== undefined);

    await deletePasskey(sessionId, credentialId);

    const response = {
        statusCode: 204,
    };

    return response;
};
