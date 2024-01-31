import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId, handleSignUp } from '../lib/service.js';
import assert from 'node:assert';

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null);

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    await handleSignUp(event.body, sessionId);

    const response = {
        statusCode: 302,
        headers: {
            'Location': '/'
        },
    };

    return response;
};
