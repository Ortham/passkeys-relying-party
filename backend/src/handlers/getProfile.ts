import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getProfile, getSessionId } from '../lib/session.js';

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    const sessionId = getSessionId(event.headers);

    const profile = sessionId === undefined ? undefined : await getProfile(sessionId);

    let response;
    if (profile) {
        response = {
            statusCode: 200,
            body: JSON.stringify(profile)
        }
    } else {
        response = {
            statusCode: 401
        };
    }

    return response;
};
