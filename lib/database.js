class Database {
    constructor() {
        this.users = new Map();
        this.sessions = new Map();
    }

    insertUser(user) {
        this.users.set(user.id.toString('base64'), user);
    }

    getUser(userId) {
        console.log(this.users);
        return this.users.get(userId.toString('base64'));
    }

    insertSession(sessionId) {
        this.sessions.set(sessionId, {});
    }

    updateSessionChallenge(sessionId, challenge) {
        const session = this.sessions.get(sessionId);
        session.challenge = challenge;
    }

    updateSessionUserId(sessionId, userId) {
        const session = this.sessions.get(sessionId);
        session.userId = userId.toString('base64');
    }

    getSession(sessionId) {
        return this.sessions.get(sessionId);
    }

    getChallenge(sessionId) {
        return this.getSession(sessionId).challenge;
    }

    getUserBySessionId(sessionId) {
        const userId = this.sessions.get(sessionId).userId;

        return this.getUser(userId);
    }

    deleteSession(sessionId) {
        this.sessions.delete(sessionId);
    }

    countUsersByCredentialId(credentialId) {
        const passkeyId = credentialId.toString('base64url');
        let count = 0;

        for (const [_id, user] of this.users) {
            if (user.passkey.id === passkeyId) {
                count += 1;
            }
        }

        return count;
    }

    updatePasskeyState(userId, signCount, backupState) {
        const user = this.users.get(userId.toString('base64'));

        user.passkey.signCount = signCount;
        user.passkey.backupState = backupState;
    }
};

export const database = new Database();
