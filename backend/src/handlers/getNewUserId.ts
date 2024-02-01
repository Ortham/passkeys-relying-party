import { APIGatewayProxyEvent, APIGatewayProxyResult, Handler } from 'aws-lambda';
import { getRandomBytes } from '../lib/util.js';

export function createNewUserId() {
    return getRandomBytes(16).toString('base64url');
}

export const lambdaHandler: Handler = async (_event: APIGatewayProxyEvent, _context): Promise<APIGatewayProxyResult> => {
    const id = createNewUserId();

    const response = {
        statusCode: 200,
        body: JSON.stringify({
            id
        })
    };

    return response;
};
