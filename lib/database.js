class Database {
    constructor() {
        this.users = new Map();
        this.sessions = new Map();
    }

    async insertUser(user) {
        this.users.set(user.id.toString('base64'), user);
    }

    async getUser(userId) {
        return this.users.get(userId.toString('base64'));
    }

    async insertSession(sessionId) {
        this.sessions.set(sessionId, {});
    }

    async updateSessionChallenge(sessionId, challenge) {
        const session = this.sessions.get(sessionId);
        session.challenge = challenge;
    }

    async updateSessionUserId(sessionId, userId) {
        const session = this.sessions.get(sessionId);
        session.userId = userId.toString('base64');
    }

    async getSession(sessionId) {
        return this.sessions.get(sessionId);
    }

    async getChallenge(sessionId) {
        return this.sessions.get(sessionId).challenge;
    }

    async getUserBySessionId(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            return undefined;
        }

        const userId = this.sessions.get(sessionId).userId;
        if (!userId) {
            return undefined;
        }

        return this.users.get(userId.toString('base64'));
    }

    async deleteSession(sessionId) {
        this.sessions.delete(sessionId);
    }

    async countUsersByCredentialId(credentialId) {
        const passkeyId = credentialId.toString('base64url');
        let count = 0;

        for (const [_id, user] of this.users) {
            if (user.passkey.id === passkeyId) {
                count += 1;
            }
        }

        return count;
    }

    async updatePasskeyState(userId, signCount, backupState) {
        const user = this.users.get(userId.toString('base64'));

        user.passkey.signCount = signCount;
        user.passkey.backupState = backupState;
    }
};

export const database = new Database();
