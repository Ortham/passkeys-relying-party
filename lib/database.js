class Database {
    constructor() {
        this.users = new Map();
        this.challenges = new Map();
    }

    insertUser(user) {
        this.users.set(user.id.toString('base64'), user);
    }

    getUser(userId) {
        return this.users.get(userId.toString('base64'));
    }

    insertChallenge(sessionId, challenge) {
        this.challenges.set(sessionId, challenge);
    }

    getChallenge(sessionId) {
        return this.challenges.get(sessionId);
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
