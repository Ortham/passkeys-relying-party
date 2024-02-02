import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { DynamoDBClient, ReturnValue } from '@aws-sdk/client-dynamodb';
import { BatchWriteCommand, BatchWriteCommandInput, DeleteCommand, DeleteCommandInput, DynamoDBDocumentClient, GetCommand, GetCommandInput, PutCommand, PutCommandInput, UpdateCommand, UpdateCommandInput } from '@aws-sdk/lib-dynamodb';

const ENDPOINT_OVERRIDE = env['ENDPOINT_OVERRIDE'];
const USERS_TABLE_NAME = env['USERS_TABLE_NAME'];
const SESSIONS_TABLE_NAME = env['SESSIONS_TABLE_NAME'];
const PASSKEYS_TABLE_NAME = env['PASSKEYS_TABLE_NAME'];

export interface PasskeyData {
    type: 'public-key';
    credentialId: Buffer;
    userId: Buffer;
    signCount: number;
    backupState: boolean;
    uvInitialized: boolean;
    transports: string[];
    backupEligible: boolean;
    publicKey: JsonWebKey;
}

export interface User {
    id: Buffer;
    name: string;
    displayName: string;
    passkeys: Set<Buffer>;
    sessions: Set<string>;
}

interface Session {
    ttl: number;
    userId?: string;
    challenge?: Buffer;
}

interface Database {
    insertUser(user: User): Promise<void>;

    insertSession(sessionId: string): Promise<void>;

    updateSessionChallenge(sessionId: string, challenge: Buffer): Promise<void>;

    updateSessionUserId(sessionId: string, userId: Buffer): Promise<void>;

    sessionExists(sessionId: string): Promise<boolean>;

    getChallenge(sessionId: string): Promise<Buffer | undefined>;

    getUserBySessionId(sessionId: string): Promise<User | undefined>;

    // Deletes the user associated with the given session ID, and all their sessions and passkeys.
    deleteUserBySessionId(sessionId: string): Promise<void>;

    deleteSession(sessionId: string): Promise<void>;

    insertPasskey(passkey: PasskeyData): Promise<void>;

    passkeyExists(credentialId: Buffer): Promise<boolean>;

    getPasskeyData(credentialId: Buffer): Promise<PasskeyData | undefined>;

    updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean): Promise<void>;
}

function hasSessionExpired(session: Session) {
    return session.ttl <= Math.floor(Date.now() / 1000);
}

function getExpiryTimestamp() {
    const now = Math.floor(Date.now() / 1000);
    return now + 86400 * 3; // The session will expire 3 days from now.
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
            ttl: getExpiryTimestamp()
        });
    }

    async updateSessionChallenge(sessionId: string, challenge: Buffer) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.challenge = challenge;
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
            const user = this.users.get(session.userId);
            if (!user) {
                throw new Error(`User with ID ${userId} is undefined`);
            }

            user.sessions.delete(sessionId);
        }

        // Update the session's user ID
        session.userId = userId.toString('base64');

        // Update the user's sessions.
        const user = this.users.get(session.userId);
        if (!user) {
            throw new Error(`User with ID ${userId} is undefined`);
        }

        user.sessions.add(sessionId);
    }

    async sessionExists(sessionId: string) {
        const session = this.sessions.get(sessionId);
        return session !== undefined && !hasSessionExpired(session);
    }

    async getChallenge(sessionId: string) {
        const session = this.sessions.get(sessionId);
        if (session && !hasSessionExpired(session)) {
            return session.challenge;
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

        return this.users.get(userId);
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
            this.passkeys.delete(id.toString('base64'));
        }

        this.users.delete(user.id.toString('base64'));
    }

    async deleteSession(sessionId: string) {
        const session = this.sessions.get(sessionId);

        // Update the user's sessions.
        if (session && session.userId) {
            const user = this.users.get(session.userId);
            user?.sessions.delete(sessionId);
        }

        this.sessions.delete(sessionId);
    }

    async insertPasskey(passkey: PasskeyData) {
        this.passkeys.set(passkey.credentialId.toString('base64'), passkey);

        const user = this.users.get(passkey.userId.toString('base64'));
        if (!user) {
            throw new Error(`User with ID ${passkey.userId} is undefined`);
        }

        user.passkeys.add(passkey.credentialId);
    };

    async passkeyExists(credentialId: Buffer) {
        return this.passkeys.has(credentialId.toString('base64'));
    }

    async getPasskeyData(credentialId: Buffer) {
        const passkey = this.passkeys.get(credentialId.toString('base64'));
        if (!passkey) {
            throw new Error(`Passkey with ID ${credentialId} is undefined`);
        }

        return passkey;
    }

    async updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean) {
        const passkey = this.passkeys.get(credentialId.toString('base64'));
        if (!passkey) {
            throw new Error(`Passkey with ID ${credentialId} is undefined`);
        }

        passkey.signCount = signCount;
        passkey.backupState = backupState;
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
        const item: Omit<User, 'passkeys' | 'sessions'> & Partial<User> = Object.assign({}, user);
        if (user.passkeys.size === 0) {
            delete item.passkeys;
        }
        if (user.sessions.size === 0) {
            delete item.sessions;
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
                ttl: getExpiryTimestamp()
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
                ":challenge": challenge
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

    async getChallenge(sessionId: string): Promise<Buffer | undefined> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ProjectionExpression: 'challenge'
        };

        const session = await this.get(params);

        if (session === undefined || hasSessionExpired(session as Session)) {
            return undefined;
        }

        // challenge is deserialised as a Uint8Array.
        return Buffer.from(session['challenge']);
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
            // user.id is deserialised as a Uint8Array.
            user['id'] = Buffer.from(user['id']);
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
            // item.credentialId and item.userId are deserialised as Uint8Array values.
            item['credentialId'] = Buffer.from(item['credentialId']);
            item['userId'] = Buffer.from(item['userId']);
        }
        return item as PasskeyData | undefined;
    }

    async updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean): Promise<void> {
        const params = {
            TableName: PASSKEYS_TABLE_NAME,
            Key: {
                credentialId
            },
            UpdateExpression: "set signCount = :s, backupState = :b",
            ExpressionAttributeValues: {
                ":s": signCount,
                ":b": backupState
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
