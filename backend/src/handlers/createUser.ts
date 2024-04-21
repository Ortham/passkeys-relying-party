import { APIGatewayProxyEvent, Handler } from 'aws-lambda';
import assert from 'node:assert';
import { Buffer } from 'node:buffer';
import { getSessionId } from '../lib/session.js';
import { User, database } from '../lib/database.js';
import {
    parseRequestBody as parseCreatePasskeyRequestBody,
    RequestBody as CreatePasskeyRequestBody,
    validatePasskeyInputs,
    createPasskeyObject,
} from './createPasskey.js';
import { getRandomBytes } from '../lib/util.js';

interface RequestBody {
    userHandle: Buffer;
    username: string;
    displayName: string;
    passkey: Omit<CreatePasskeyRequestBody, 'description'>;
}

function assertPasskeyJsonIsValid(
    value: unknown,
): asserts value is RequestBody['passkey'] & { attestationObject: string } {
    assert.strictEqual(typeof value, 'object', 'Value is not an object');
    assert(value !== null, 'Value is null');

    const rbValue = value as CreatePasskeyRequestBody;

    assert.strictEqual(
        typeof rbValue.clientData,
        'object',
        'clientData is not an object',
    );
    assert(rbValue.clientData !== null, 'clientData is null');

    assert.strictEqual(
        typeof rbValue.clientData.type,
        'string',
        'clientData.type is not a string',
    );
    assert.strictEqual(
        typeof rbValue.clientData.challenge,
        'string',
        'clientData.challenge is not a string',
    );
    assert.strictEqual(
        typeof rbValue.clientData.origin,
        'string',
        'clientData.origin is not a string',
    );

    assert.strictEqual(
        typeof (value as { attestationObject: string }).attestationObject,
        'string',
        'attestationObject is not a string',
    );

    assert(Array.isArray(rbValue.transports), 'transports is not an array');
    assert(
        rbValue.transports.every((e) => typeof e === 'string'),
        'transports array contains a non-string member',
    );
}

function assertParsedJsonIsValid(
    value: unknown,
): asserts value is Omit<RequestBody, 'userHandle'> & { userHandle: string } {
    assert.strictEqual(typeof value, 'object', 'Value is not an object');
    assert(value !== null, 'Value is null');

    const rbValue = value as RequestBody;

    assert.strictEqual(
        typeof rbValue.userHandle,
        'string',
        'userHandle is not a string',
    );
    assert.strictEqual(
        typeof rbValue.username,
        'string',
        'username is not a string',
    );
    assert.strictEqual(
        typeof rbValue.displayName,
        'string',
        'displayName is not a string',
    );

    assertPasskeyJsonIsValid(rbValue.passkey);
}

function parseRequestBody(body: string): RequestBody {
    const json: unknown = JSON.parse(body);

    assertParsedJsonIsValid(json);

    assert(json.username !== null, 'Username is not in request body');
    assert(json.displayName !== null, 'Display name is not in request body');
    assert(json.userHandle !== null, 'User handle is not in request body');
    assert(json.passkey !== null, 'Passkey data is not in request body');

    const passkey = parseCreatePasskeyRequestBody(JSON.stringify(json.passkey));

    return {
        userHandle: Buffer.from(json.userHandle, 'base64'),
        username: json.username,
        displayName: json.displayName,
        passkey,
    };
}

function createUserObject(requestBody: RequestBody): User {
    return {
        id: getRandomBytes(16),
        userHandle: requestBody.userHandle,
        name: requestBody.username,
        displayName: requestBody.displayName,
        passkeys: new Set(),
        sessions: new Set(),
    };
}

export async function createUser(bodyString: string, sessionId: string) {
    const body = parseRequestBody(bodyString);
    console.log('Request body is', body);

    const user = createUserObject(body);

    const jwk = await validatePasskeyInputs(body.passkey, sessionId);
    const passkey = createPasskeyObject(
        body.passkey,
        user,
        jwk,
        'Added during account creation',
    );

    // Store the user first because storing the passkey also updates the user data with the passkey's ID.
    await database.insertUser(user);
    await database.insertPasskey(passkey);
    console.log('Stored user', user, 'and passkey', passkey);

    await database.updateSessionUserId(sessionId, user.id);
}

export const lambdaHandler: Handler = async (
    event: APIGatewayProxyEvent,
    _context,
) => {
    assert(event.body !== null, 'The request has no body');

    const sessionId = getSessionId(event.headers);
    assert(sessionId !== undefined, 'The request has no session ID');

    await createUser(event.body, sessionId);

    const response = {
        statusCode: 204,
    };

    return response;
};
