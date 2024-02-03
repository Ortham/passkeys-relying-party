import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import assert from 'node:assert';
import { Buffer } from 'node:buffer';
import { getSessionId } from '../lib/session.js';
import { User, database } from '../lib/database.js';
import { parseRequestBody as parseCreatePasskeyRequestBody, RequestBody as CreatePasskeyRequestBody, validatePasskeyInputs, createPasskeyObject } from './createPasskey.js';
import { getRandomBytes } from '../lib/util.js';

interface RequestBody {
    userHandle: Buffer;
    username: string;
    displayName: string;
    passkey: Omit<CreatePasskeyRequestBody, 'description'>;
}

function parseSignUpBody(body: string): RequestBody {
    const parameters = new URLSearchParams(body);

    const username = parameters.get('username');
    const displayName = parameters.get('displayName');
    const userHandle = parameters.get('userHandle');
    const passkeyJSON = parameters.get('passkey');

    assert(username !== null);
    assert(displayName !== null);
    assert(userHandle !== null);
    assert(passkeyJSON !== null);

    const passkey = parseCreatePasskeyRequestBody(passkeyJSON);

    return {
        userHandle: Buffer.from(userHandle, 'base64'),
        username,
        displayName,
        passkey
    };
}

function createUserObject(requestBody: RequestBody): User {
    return {
        id: getRandomBytes(16),
        userHandle: requestBody.userHandle,
        name: requestBody.username,
        displayName: requestBody.displayName,
        passkeys: new Set(),
        sessions: new Set()
    };
}

export async function createUser(bodyString: string, sessionId: string) {
    const body = parseSignUpBody(bodyString);
    console.log('Request body is', body);

    const user = createUserObject(body);

    const jwk = await validatePasskeyInputs(body.passkey, sessionId);
    const passkey = createPasskeyObject(body.passkey, user, jwk, 'Added during account creation');

    // Store the user first because storing the passkey also updates the user data with the passkey's ID.
    await database.insertUser(user);
    await database.insertPasskey(passkey);
    console.log('Stored user', user, 'and passkey', passkey);

    await database.updateSessionUserId(sessionId, user.id);
}

export const lambdaHandler: Handler = async (event: APIGatewayProxyEvent, _context) => {
    assert(event.body !== null);

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined);

    await createUser(event.body, sessionId);

    const response = {
        statusCode: 302,
        headers: {
            'Location': '/'
        },
    };

    return response;
};
