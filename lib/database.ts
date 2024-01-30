
interface PasskeyData {
    type: 'public-key';
    id: string;
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
    passkeys: PasskeyData[];
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

    passkeyExists(credentialId: Buffer): Promise<boolean>;

    getUserPasskeyData(userId: Buffer, credentialId: string): Promise<PasskeyData | undefined>;

    updatePasskeyState(userId: Buffer, credentialId: string, signCount: number, backupState: boolean): Promise<void>;
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

    async passkeyExists(credentialId: Buffer) {
        const passkeyId = credentialId.toString('base64url');
        let count = 0;

        for (const [_id, user] of this.users) {
            for (const passkey of user.passkeys) {
                if (passkey.id === passkeyId) {
                    count += 1;
                }
            }
        }

        return count > 0;
    }

    async getUserPasskeyData(userId: Buffer, credentialId: string) {
        const user = this.users.get(userId.toString('base64'));
        if (!user) {
            throw new Error(`User with ID ${userId} is undefined`);
        }

        return user.passkeys.find(passkey => passkey.id === credentialId);
    }

    async updatePasskeyState(userId: Buffer, credentialId: string, signCount: number, backupState: boolean) {
        const user = this.users.get(userId.toString('base64'));
        if (!user) {
            throw new Error(`User with ID ${userId} is undefined`);
        }

        const passkey = user.passkeys.find(passkey => passkey.id === credentialId);
        if (!passkey) {
            throw new Error(`Passkey with ID ${credentialId} is undefined`);
        }

        passkey.signCount = signCount;
        passkey.backupState = backupState;
    }
};

export const database: Database = new InProcessDatabase();
