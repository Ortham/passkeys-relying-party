import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId, handleSignIn } from '../lib/service.js';
import assert from 'node:assert';

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null);

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    const isValid = await handleSignIn(event.body, sessionId);

    let response;
    if (isValid) {
        response = {
            statusCode: 302,
            headers: {
                'Location': '/'
            },
        };
    } else {
        response = {
            statusCode: 400,
            headers: {
                'Content-Type': 'text/html'
            },
            body: '<!DOCTYPE html><html><head><meta charset="utf-8" /></head><body><p>Authentication failed!</p></body></html>'
        }
    }

    return response;
};
