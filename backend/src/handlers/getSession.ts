import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId } from '../lib/session.js';
import { database } from '../lib/database.js';
import assert from 'node:assert';

export async function getSession(sessionId: string) {
    const session = await database.getSession(sessionId);

    if (session === undefined) {
        return undefined;
    }

    return {
        ttl: session.ttl,
        userId: session.userId?.toString('base64url'),
    };
}

export const lambdaHandler: Handler = async (
    event: APIGatewayProxyEvent,
    _context,
) => {
    const sessionId = getSessionId(event.headers);
    assert(
        sessionId !== undefined,
        'Session ID is not defined when getting session',
    );

    const session = await getSession(sessionId);

    let response;
    if (session) {
        response = {
            statusCode: 200,
            body: JSON.stringify(session),
        };
    } else {
        response = {
            statusCode: 404,
        };
    }

    return response;
};
