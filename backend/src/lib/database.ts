import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { DynamoDBClient, ReturnValue } from '@aws-sdk/client-dynamodb';
import { BatchWriteCommand, BatchWriteCommandInput, DeleteCommand, DeleteCommandInput, DynamoDBDocumentClient, GetCommand, GetCommandInput, PutCommand, PutCommandInput, UpdateCommand, UpdateCommandInput } from '@aws-sdk/lib-dynamodb';
import { getCurrentTimestamp } from './util.js';

const ENDPOINT_OVERRIDE = env['ENDPOINT_OVERRIDE'];
const USERS_TABLE_NAME = env['USERS_TABLE_NAME'];
const SESSIONS_TABLE_NAME = env['SESSIONS_TABLE_NAME'];
const PASSKEYS_TABLE_NAME = env['PASSKEYS_TABLE_NAME'];

const CHALLENGE_TIMEOUT_SECS = 600;
const SESSION_TIMEOUT_SECS = 86400 * 3;

export interface PasskeyData {
    type: 'public-key';
    credentialId: Buffer;
    userId: Buffer;
    userHandle: Buffer; // Store a copy of the user handle to avoid another DB lookup.
    signCount: number;
    backupState: boolean;
    uvInitialized: boolean;
    transports: string[];
    backupEligible: boolean;
    publicKey: JsonWebKey;
    description: string;
    createdTimestamp: number;
    lastUsedTimestamp?: number;
}

export interface User {
    id: Buffer;
    name: string;
    displayName: string;
    userHandle: Buffer; // The user handle/id that is associated with the user's passkeys
    passkeys: Set<string>;
    sessions: Set<string>;
}

interface Session {
    ttl: number;
    userId?: Buffer;
    challenge?: {
        value: Buffer;
        ttl: number;
    };
}

interface Database {
    insertUser(user: User): Promise<void>;

    insertSession(sessionId: string): Promise<void>;

    updateSessionChallenge(sessionId: string, challenge: Buffer): Promise<void>;

    updateSessionUserId(sessionId: string, userId: Buffer): Promise<void>;

    sessionExists(sessionId: string): Promise<boolean>;

    getSession(sessionId: string): Promise<Session | undefined>;

    getAndDeleteChallenge(sessionId: string): Promise<Buffer | undefined>;

    getUserBySessionId(sessionId: string): Promise<User | undefined>;

    // Deletes the user associated with the given session ID, and all their sessions and passkeys.
    deleteUserBySessionId(sessionId: string): Promise<void>;

    deleteSession(sessionId: string): Promise<void>;

    insertPasskey(passkey: PasskeyData): Promise<void>;

    deletePasskey(credentialId: Buffer): Promise<void>;

    passkeyExists(credentialId: Buffer): Promise<boolean>;

    getPasskeyData(credentialId: Buffer): Promise<PasskeyData | undefined>;

    updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean): Promise<void>;
}

function hasSessionExpired(session: Session) {
    return session.ttl <= getCurrentTimestamp();
}

function hasChallengeExpired(challenge: Required<Session>['challenge']) {
    return challenge.ttl < getCurrentTimestamp();
}

function getSessionExpiryTimestamp() {
    return getCurrentTimestamp() + SESSION_TIMEOUT_SECS;
}

function getChallengeExpiryTimestamp() {
    return getCurrentTimestamp() + CHALLENGE_TIMEOUT_SECS;
}

class InProcessDatabase implements Database {
    private users: Map<string, User>;
    private sessions: Map<string, Session>;
    private passkeys: Map<string, PasskeyData>;

    constructor() {
        this.users = new Map();
        this.sessions = new Map();
        this.passkeys = new Map();
    }

    async insertUser(user: User) {
        this.users.set(user.id.toString('base64'), user);
    }

    async insertSession(sessionId: string) {
        this.sessions.set(sessionId, {
            ttl: getSessionExpiryTimestamp()
        });
    }

    async updateSessionChallenge(sessionId: string, challenge: Buffer) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.challenge = {
                value: challenge,
                ttl: getChallengeExpiryTimestamp()
            };
        } else {
            throw new Error(`Session with ID ${sessionId} is undefined`);
        }
    }

    async updateSessionUserId(sessionId: string, userId: Buffer) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error(`Session with ID ${sessionId} is undefined`);
        }

        // If the session already had a user ID associated with it, remove the session ID from that user's sessions set.
        if (session.userId !== undefined) {
            const user = this.users.get(session.userId.toString('base64'));
            if (!user) {
                throw new Error(`User with ID ${userId} is undefined`);
            }

            user.sessions.delete(sessionId);
        }

        // Update the session's user ID
        session.userId = userId;

        // Update the user's sessions.
        const user = this.users.get(userId.toString('base64'));
        if (!user) {
            throw new Error(`User with ID ${userId} is undefined`);
        }

        user.sessions.add(sessionId);
    }

    async sessionExists(sessionId: string) {
        const session = await this.getSession(sessionId);
        return session !== undefined;
    }

    async getSession(sessionId: string): Promise<Session | undefined> {
        const session = this.sessions.get(sessionId);
        if (session !== undefined && !hasSessionExpired(session)) {
            return session;
        }

        return undefined;
    }

    async getAndDeleteChallenge(sessionId: string) {
        const session = this.sessions.get(sessionId);
        if (session && !hasSessionExpired(session)) {
            const challenge = session.challenge;
            delete session.challenge;

            if (challenge !== undefined && !hasChallengeExpired(challenge)) {
                return challenge.value;
            }

            return undefined;
        } else {
            throw new Error(`Session with ID ${sessionId} is undefined`);
        }
    }

    async getUserBySessionId(sessionId: string) {
        const session = this.sessions.get(sessionId);
        if (!session || hasSessionExpired(session)) {
            return undefined;
        }

        const userId = session.userId;
        if (!userId) {
            return undefined;
        }

        return this.users.get(userId.toString('base64'));
    }

    async deleteUserBySessionId(sessionId: string) {
        const user = await this.getUserBySessionId(sessionId);
        if (!user) {
            return;
        }

        for (const id of user.sessions) {
            this.sessions.delete(id);
        }

        for (const id of user.passkeys) {
            this.passkeys.delete(id);
        }

        this.users.delete(user.id.toString('base64'));
    }

    async deleteSession(sessionId: string) {
        const session = this.sessions.get(sessionId);

        // Update the user's sessions.
        if (session && session.userId) {
            const user = this.users.get(session.userId.toString('base64'));
            user?.sessions.delete(sessionId);
        }

        this.sessions.delete(sessionId);
    }

    async insertPasskey(passkey: PasskeyData) {
        const key = passkey.credentialId.toString('base64');

        this.passkeys.set(key, passkey);

        const user = this.users.get(passkey.userId.toString('base64'));
        if (!user) {
            throw new Error(`User with ID ${passkey.userId} is undefined`);
        }

        user.passkeys.add(key);
    };

    async deletePasskey(credentialId: Buffer): Promise<void> {
        const key = credentialId.toString('base64');
        const passkey = this.passkeys.get(key);
        if (!passkey) {
            return;
        }

        const user = this.users.get(passkey.userId.toString('base64'));
        if (user) {
            user.passkeys.delete(key);
        }

        this.passkeys.delete(key);
    }

    async passkeyExists(credentialId: Buffer) {
        return this.passkeys.has(credentialId.toString('base64'));
    }

    async getPasskeyData(credentialId: Buffer) {
        return this.passkeys.get(credentialId.toString('base64'));
    }

    async updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean) {
        const passkey = this.passkeys.get(credentialId.toString('base64'));
        if (!passkey) {
            throw new Error(`Passkey with ID ${credentialId} is undefined`);
        }

        passkey.signCount = signCount;
        passkey.backupState = backupState;
        passkey.lastUsedTimestamp = getCurrentTimestamp();
    }
}


function idsToDeleteRequests(
    ids: Set<Buffer | string>,
    keyMapper: (id: Buffer | string) => Record<string, Buffer | string>
) {
    const items = [];
    for (const id of ids.values()) {
        items.push({
            DeleteRequest: {
                Key: keyMapper(id)
            }
        });
    }

    return items;
}

class DynamoDbDatabase implements Database {
    private ddbDocClient: DynamoDBDocumentClient;

    constructor() {
        const ddbConfig = ENDPOINT_OVERRIDE ? { endpoint: ENDPOINT_OVERRIDE } : {};
        const ddbClient = new DynamoDBClient(ddbConfig);

        this.ddbDocClient = DynamoDBDocumentClient.from(ddbClient);
    }

    async insertUser(user: User) {
        type DbUser = Omit<User, 'passkeys' | 'sessions'> & Partial<Pick<User, 'sessions'>> & { passkeys?: Set<Buffer> };

        const item: DbUser = {
            id: user.id,
            name: user.name,
            displayName: user.displayName,
            userHandle: user.userHandle
        };

        // DynamoDB doesn't allow storing empty sets by default.
        if (user.passkeys.size > 0) {
            // The passkeys set is a set of base64 strings in JavaScript but should be stored as a set of binary values in DynamoDB.
            item.passkeys = new Set<Buffer>();
            for (const id of user.passkeys.values()) {
                item.passkeys.add(Buffer.from(id, 'base64'));
            }
        }

        if (user.sessions.size > 0) {
            item.sessions = user.sessions;
        }

        const params = {
            TableName: USERS_TABLE_NAME,
            Item: item
        };

        await this.put(params);
    }

    async insertSession(sessionId: string): Promise<void> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Item: {
                id: sessionId,
                ttl: getSessionExpiryTimestamp()
            }
        };

        await this.put(params);
    }

    async updateSessionChallenge(sessionId: string, challenge: Buffer): Promise<void> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            UpdateExpression: "set challenge = :challenge",
            ExpressionAttributeValues: {
                ":challenge": {
                    value: challenge,
                    ttl: getChallengeExpiryTimestamp()
                }
            }
        }

        await this.update(params);
    }

    async updateSessionUserId(sessionId: string, userId: Buffer): Promise<void> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            UpdateExpression: "set userId = :userId",
            ExpressionAttributeValues: {
                ":userId": userId
            },
            ReturnValues: ReturnValue.UPDATED_OLD
        }

        const result = await this.update(params);

        const oldUserId = result.Attributes?.['userId'];
        if (oldUserId) {
            // Remove the session from the old user's data.
            await this.removeSessionFromUser(sessionId, oldUserId);
        }

        const userParams = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: userId
            },
            UpdateExpression: "ADD sessions :sessionId",
            ExpressionAttributeValues: {
                ":sessionId": new Set([sessionId])
            }
        }

        await this.update(userParams);
    }

    async sessionExists(sessionId: string): Promise<boolean> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ProjectionExpression: 'id'
        };

        const session = await this.get(params);
        return session !== undefined && !hasSessionExpired(session as Session);
    }

    async getSession(sessionId: string): Promise<Session | undefined> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            }
        };

        const session = await this.get(params);
        if (session !== undefined && !hasSessionExpired(session as Session)) {
            session['userId'] = Buffer.from(session['userId']);
            session['challenge']['value'] = Buffer.from(session['challenge']['value']);

            return session as Session;
        }

        return undefined;
    }

    async getAndDeleteChallenge(sessionId: string): Promise<Buffer | undefined> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            UpdateExpression: "REMOVE challenge",
            ReturnValues: ReturnValue.ALL_OLD
        }

        const result = await this.update(params);
        if (result.Attributes === undefined || hasSessionExpired(result.Attributes as Session)) {
            return undefined;
        }

        const challenge = result.Attributes['challenge'];
        if (challenge === undefined || hasChallengeExpired(challenge)) {
            return undefined;
        }

        // challenge.value is deserialised as a Uint8Array.
        return Buffer.from(challenge.value);
    }

    async getUserBySessionId(sessionId: string): Promise<User | undefined> {
        const userId = await this.getSessionUserId(sessionId);
        if (!userId) {
            return undefined;
        }

        const userParams = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: userId
            }
        };

        const user = await this.get(userParams);
        if (user !== undefined) {
            // id and userHandle are deserialised as Uint8Arrays.
            user['id'] = Buffer.from(user['id']);
            user['userHandle'] = Buffer.from(user['userHandle']);

            if (user['passkeys'] === undefined) {
                user['passkeys'] = new Set();
            } else {
                // The passkeys set should be turned into a set of strings.
                const passkeys = new Set();
                for (const id of user['passkeys']) {
                    passkeys.add(Buffer.from(id).toString('base64'));
                }
                user['passkeys'] = passkeys;
            }

            if (user['sessions'] === undefined) {
                user['sessions'] = new Set();
            }
        }

        return user as User | undefined;
    }

    async deleteUserBySessionId(sessionId: string) {
        const userId = await this.getSessionUserId(sessionId);
        if (!userId) {
            return;
        }

        const params = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: userId
            },
            ReturnValues: ReturnValue.ALL_OLD
        };
        const attributes = await this.delete(params);

        const passkeyIds: Set<Buffer> = attributes?.['passkeys'] ?? new Set();
        console.log('Deleting passkeys with IDs', passkeyIds);

        const sessionIds = attributes?.['sessions'] ?? new Set();
        console.log('Deleting sessions with IDs', sessionIds);

        const batchDeleteParams: BatchWriteCommandInput = {
            RequestItems: {
                [PASSKEYS_TABLE_NAME!]: idsToDeleteRequests(passkeyIds, id => ({ credentialId: id })),
                [SESSIONS_TABLE_NAME!]: idsToDeleteRequests(sessionIds, id => ({ id })),
            }
        }

        await this.batchDelete(batchDeleteParams);
    }

    async deleteSession(sessionId: string): Promise<void> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ReturnValues: ReturnValue.ALL_OLD
        };

        const attributes = await this.delete(params);
        const userId = attributes?.['userId'];

        if (!userId) {
            return;
        }

        // Remove the session from the user's data.
        await this.removeSessionFromUser(sessionId, userId);
    }

    async insertPasskey(passkey: PasskeyData): Promise<void> {
        const passkeyParams = {
            TableName: PASSKEYS_TABLE_NAME,
            Item: passkey
        };

        await this.put(passkeyParams);

        const userParams = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: passkey.userId
            },
            UpdateExpression: "ADD passkeys :passkeyId",
            ExpressionAttributeValues: {
                ":passkeyId": new Set([passkey.credentialId])
            }
        }

        await this.update(userParams);
    }

    async deletePasskey(credentialId: Buffer): Promise<void> {
        const params = {
            TableName: PASSKEYS_TABLE_NAME,
            Key: {
                credentialId
            },
            ReturnValues: ReturnValue.ALL_OLD
        };

        const attributes = await this.delete(params);
        const userId = attributes?.['userId'];

        if (!userId) {
            return;
        }

        const userParams = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: userId
            },
            UpdateExpression: "DELETE passkeys :credentialId",
            ExpressionAttributeValues: {
                ":credentialId": new Set([credentialId])
            }
        }

        await this.update(userParams);
    }

    async passkeyExists(credentialId: Buffer): Promise<boolean> {
        const params = {
            TableName: PASSKEYS_TABLE_NAME,
            Key: {
                credentialId
            },
            ProjectionExpression: 'credentialId'
        };

        const item = await this.get(params);
        return item !== undefined;
    }

    async getPasskeyData(credentialId: Buffer): Promise<PasskeyData | undefined> {
        const params = {
            TableName: PASSKEYS_TABLE_NAME,
            Key: {
                credentialId
            }
        }

        const item = await this.get(params);
        if (item !== undefined) {
            // credentialId, userId and userHandle are deserialised as Uint8Array values.
            item['credentialId'] = Buffer.from(item['credentialId']);
            item['userId'] = Buffer.from(item['userId']);
            item['userHandle'] = Buffer.from(item['userHandle']);
        }
        return item as PasskeyData | undefined;
    }

    async updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean): Promise<void> {
        const params = {
            TableName: PASSKEYS_TABLE_NAME,
            Key: {
                credentialId
            },
            UpdateExpression: "set signCount = :s, backupState = :b, lastUsedTimestamp = :l",
            ExpressionAttributeValues: {
                ":s": signCount,
                ":b": backupState,
                ":l": getCurrentTimestamp()
            }
        }

        await this.update(params);
    }

    private async put(params: PutCommandInput) {
        try {
            const data = await this.ddbDocClient.send(new PutCommand(params));
            console.log("Success - item added or updated", data);
        } catch (err) {
            console.error("Error adding or updating item:", err);

            throw err;
        }
    }

    private async update(params: UpdateCommandInput) {
        try {
            const data = await this.ddbDocClient.send(new UpdateCommand(params));
            console.log("Success - item updated", data);
            return data;
        } catch (err) {
            console.error("Error adding or updating item:", err);
            throw err;
        }
    }

    private async get(params: GetCommandInput) {
        try {
            const result = await this.ddbDocClient.send(new GetCommand(params));
            return result.Item;
        } catch (err) {
            console.error("Error getting item:", err);
            throw err;
        }
    }

    private async getSessionUserId(sessionId: string): Promise<Buffer | undefined> {
        const sessionParams = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ProjectionExpression: 'userId'
        };

        const session = await this.get(sessionParams);


        if (session === undefined || hasSessionExpired(session as Session)) {
            return undefined;
        }

        return session['userId'];
    }

    private async delete(params: DeleteCommandInput) {
        try {
            const result = await this.ddbDocClient.send(new DeleteCommand(params));
            return result.Attributes;
        } catch (err) {
            console.error("Error deleting item:", err);
            throw err;
        }
    }

    private async batchDelete(params: BatchWriteCommandInput) {
        try {
            await this.ddbDocClient.send(new BatchWriteCommand(params));
        } catch (err) {
            console.error("Error batch-deleting items:", err);
            throw err;
        }
    }

    private async removeSessionFromUser(sessionId: string, userId: Buffer) {
        const userParams = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: userId
            },
            UpdateExpression: "DELETE sessions :sessionId",
            ExpressionAttributeValues: {
                ":sessionId": new Set([sessionId])
            }
        }

        await this.update(userParams);
    }
}

export const database: Database = env['AWS_REGION'] ? new DynamoDbDatabase() : new InProcessDatabase();
