import {
    APIGatewayProxyEvent,
    APIGatewayProxyResult,
    Handler,
} from 'aws-lambda';
import { createChallenge, getOrCreateSession } from '../lib/session.js';

export const lambdaHandler: Handler = async (
    event: APIGatewayProxyEvent,
    _context,
): Promise<APIGatewayProxyResult> => {
    const { sessionId, responseHeaders } = await getOrCreateSession(
        event.headers,
    );

    const challenge = await createChallenge(sessionId);

    const response = {
        statusCode: 200,
        headers: responseHeaders,
        body: JSON.stringify({
            challenge,
        }),
    };

    return response;
};
