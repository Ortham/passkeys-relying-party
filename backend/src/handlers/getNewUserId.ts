import { APIGatewayProxyEvent, APIGatewayProxyResult, Handler } from 'aws-lambda';
import { createNewUserId } from '../lib/service.js';

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
