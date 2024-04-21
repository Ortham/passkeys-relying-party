import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId, logout } from '../lib/session.js';

export const lambdaHandler: Handler = async (
    event: APIGatewayProxyEvent,
    _context,
) => {
    const sessionId = getSessionId(event.headers);

    const responseHeaders =
        sessionId === undefined ? {} : await logout(sessionId);

    const response = {
        statusCode: 204,
        headers: responseHeaders,
    };

    return response;
};
