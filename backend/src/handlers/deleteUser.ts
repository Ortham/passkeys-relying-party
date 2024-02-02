import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId, logout } from '../lib/session.js';
import { database } from '../lib/database.js';
import assert from 'node:assert';

export async function deleteUser(sessionId: string) {
    await database.deleteUserBySessionId(sessionId);

    return logout(sessionId);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    const responseHeaders = await deleteUser(sessionId);

    const response = {
        statusCode: 302,
        headers: {
            ...responseHeaders,
            'Location': '/'
        }
    };

    return response;
};
