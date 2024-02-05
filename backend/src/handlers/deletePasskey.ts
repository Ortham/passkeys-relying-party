import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId } from '../lib/session.js';
import { database } from '../lib/database.js';
import assert from 'node:assert';

export async function deletePasskey(sessionId: string, credentialIdString: string) {
    // First check that the current user owns the given credential, then remove it.
    const credentialId = Buffer.from(credentialIdString, 'base64url');

    const user = await database.getUserBySessionId(sessionId);
    assert(user !== undefined, 'No user found for the given session ID');

    assert(user.passkeys.size > 1, 'The user does not have more than one passkey');
    assert(user.passkeys.has(credentialId.toString('base64')), 'The given credential ID is not for one of the user\'s passkeys');

    await database.deletePasskey(credentialId);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined, 'The request has no session ID');

    const credentialId = event.pathParameters?.['credentialId'];
    assert(credentialId !== undefined, 'The request does not provide a credential ID');

    await deletePasskey(sessionId, credentialId);

    const response = {
        statusCode: 204,
    };

    return response;
};
