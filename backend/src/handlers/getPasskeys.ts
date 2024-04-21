import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import { getSessionId } from '../lib/session.js';
import { database } from '../lib/database.js';
import assert from 'node:assert';

export async function getPasskeys(sessionId: string) {
    const user = await database.getUserBySessionId(sessionId);
    if (!user) {
        return undefined;
    }

    const promises = [];
    for (const id of user.passkeys.values()) {
        promises.push(database.getPasskeyData(Buffer.from(id, 'base64')));
    }

    const passkeys = await Promise.all(promises);

    return passkeys
        .filter((p) => !!p)
        .map((passkey) => {
            assert(
                passkey !== undefined,
                "No passkey found for one of the user's credential IDs",
            );
            return {
                id: passkey.credentialId.toString('base64url'),
                description: passkey.description,
                createdTimestamp: passkey.createdTimestamp,
                lastUsedTimestamp: passkey.lastUsedTimestamp,
            };
        });
}

export const lambdaHandler: Handler = async (
    event: APIGatewayProxyEvent,
    _context,
) => {
    const sessionId = getSessionId(event.headers);
    if (sessionId === undefined) {
        return {
            statusCode: 401,
        };
    }

    const passkeys = await getPasskeys(sessionId);
    if (passkeys === undefined) {
        return {
            statusCode: 401,
        };
    }

    const response = {
        statusCode: 200,
        body: JSON.stringify(passkeys),
    };

    return response;
};
