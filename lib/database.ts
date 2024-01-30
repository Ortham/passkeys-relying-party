export interface User {
    id: Buffer;
    name: string;
    displayName: string;
    passkey: {
        type: 'public-key';
        id: string;
        signCount: number;
        backupState: boolean;
        uvInitialized: boolean;
        transports: string[];
        backupEligible: boolean;
        publicKey: JsonWebKey;
    };
}

interface Session {
    userId?: string;
    challenge?: Buffer;
}

interface Database {
    insertUser(user: User): Promise<void>;

    getUser(userId: Buffer): Promise<User | undefined>;

    insertSession(sessionId: string): Promise<void>;

    updateSessionChallenge(sessionId: string, challenge: Buffer): Promise<void>;

    updateSessionUserId(sessionId: string, userId: Buffer): Promise<void>;

    sessionExists(sessionId: string): Promise<boolean>;

    getChallenge(sessionId: string): Promise<Buffer | undefined>;

    getUserBySessionId(sessionId: string): Promise<User | undefined>;

    deleteSession(sessionId: string): Promise<void>;

    credentialExists(credentialId: Buffer): Promise<boolean>;

    updatePasskeyState(userId: Buffer, signCount: number, backupState: boolean): Promise<void>;
}

class InProcessDatabase implements Database {
    private users: Map<string, User>;
    private sessions: Map<string, Session>;

    constructor() {
        this.users = new Map();
        this.sessions = new Map();
    }

    async insertUser(user: User) {
        this.users.set(user.id.toString('base64'), user);
    }

    async getUser(userId: Buffer) {
        return this.users.get(userId.toString('base64'));
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

    async credentialExists(credentialId: Buffer) {
        const passkeyId = credentialId.toString('base64url');
        let count = 0;

        for (const [_id, user] of this.users) {
            if (user.passkey.id === passkeyId) {
                count += 1;
            }
        }

        return count > 0;
    }

    async updatePasskeyState(userId: Buffer, signCount: number, backupState: boolean) {
        const user = this.users.get(userId.toString('base64'));
        if (!user) {
            throw new Error(`User with ID ${userId} is undefined`);
        }

        user.passkey.signCount = signCount;
        user.passkey.backupState = backupState;
    }
};

export const database: Database = new InProcessDatabase();
