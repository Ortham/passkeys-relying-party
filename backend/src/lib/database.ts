import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, GetCommandInput, PutCommand, PutCommandInput, UpdateCommand, UpdateCommandInput } from '@aws-sdk/lib-dynamodb';

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
}

interface Session {
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

    deleteSession(sessionId: string): Promise<void>;

    insertPasskey(passkey: PasskeyData): Promise<void>;

    passkeyExists(credentialId: Buffer): Promise<boolean>;

    getPasskeyData(credentialId: Buffer): Promise<PasskeyData | undefined>;

    updatePasskeyState(credentialId: Buffer, signCount: number, backupState: boolean): Promise<void>;
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
        this.sessions.set(sessionId, {});
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
        if (session) {
            session.userId = userId.toString('base64');
        } else {
            throw new Error(`Session with ID ${sessionId} is undefined`);
        }
    }

    async sessionExists(sessionId: string) {
        return this.sessions.get(sessionId) !== undefined;
    }

    async getChallenge(sessionId: string) {
        const session = this.sessions.get(sessionId);
        if (session) {
            return session.challenge;
        } else {
            throw new Error(`Session with ID ${sessionId} is undefined`);
        }
    }

    async getUserBySessionId(sessionId: string) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            return undefined;
        }

        const userId = session.userId;
        if (!userId) {
            return undefined;
        }

        return this.users.get(userId);
    }

    async deleteSession(sessionId: string) {
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

class DynamoDbDatabase implements Database {
    private ddbDocClient: DynamoDBDocumentClient;

    constructor() {
        const ddbConfig = ENDPOINT_OVERRIDE ? { endpoint: ENDPOINT_OVERRIDE } : {};
        const ddbClient = new DynamoDBClient(ddbConfig);

        this.ddbDocClient = DynamoDBDocumentClient.from(ddbClient);
    }

    async insertUser(user: User) {
        const params = {
            TableName: USERS_TABLE_NAME,
            Item: user
        };

        await this.put(params);
    }

    async insertSession(sessionId: string): Promise<void> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Item: {
                id: sessionId
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
            }
        }

        await this.update(params);
    }

    async sessionExists(sessionId: string): Promise<boolean> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ProjectionExpression: 'id'
        };

        const item = await this.get(params);
        return item !== undefined;
    }

    async getChallenge(sessionId: string): Promise<Buffer | undefined> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ProjectionExpression: 'challenge'
        };

        const item = await this.get(params);
        // challenge is deserialised as a Uint8Array.
        return Buffer.from(item?.['challenge']);
    }

    async getUserBySessionId(sessionId: string): Promise<User | undefined> {
        const sessionParams = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            },
            ProjectionExpression: 'userId'
        };

        const session = await this.get(sessionParams);

        const userParams = {
            TableName: USERS_TABLE_NAME,
            Key: {
                id: session?.['userId']
            }
        };

        const user = await this.get(userParams);
        if (user !== undefined) {
            // user.id is deserialised as a Uint8Array.
            user['id'] = Buffer.from(user['id']);
        }
        return user as User | undefined;
    }

    async deleteSession(sessionId: string): Promise<void> {
        const params = {
            TableName: SESSIONS_TABLE_NAME,
            Key: {
                id: sessionId
            }
        };

        try {
            const data = await this.ddbDocClient.send(new DeleteCommand(params));
            console.log("Success - item deleted", data);
        } catch (err) {
            console.error("Error deleting item:", err);
            throw err;
        }
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
}

export const database: Database = env['AWS_REGION'] ? new DynamoDbDatabase() : new InProcessDatabase();
