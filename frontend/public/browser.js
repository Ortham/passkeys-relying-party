const RP_NAME = 'Passkeys Demo';

const WEBAUTHN_ALG_ES256 = -7;
const WEBAUTHN_ALG_RS256 = -257;

export async function arePasskeysSupported() {
    if (window.PublicKeyCredential &&
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        PublicKeyCredential.isConditionalMediationAvailable) {

        const results = await Promise.all([
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            PublicKeyCredential.isConditionalMediationAvailable(),
        ]);

        return results.every(result => result === true);
    } else {
        return false;
    }
}

export function toArrayBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export function toBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

export async function getChallenge() {
    const response = await fetch('/api/challenge');
    const body = await response.json();

    return toArrayBuffer(body.challenge);
}

export function handlePasskeysNotSupported() {
    console.error('Your web browser does not support passkeys!');
    document.getElementById('errorText').textContent = 'Sign up is not available because your web browser does not appear to support passkeys!';
}

export async function generatePasskey(userId, username, userDisplayName) {
    const challenge = await getChallenge();

    const passkeyCreationOptions = {
        challenge,
        rp: {
            name: RP_NAME
        },
        user: {
            id: toArrayBuffer(userId),
            name: username,
            displayName: userDisplayName
        },
        pubKeyCredParams: [
            { alg: WEBAUTHN_ALG_ES256, type: 'public-key' },
            { alg: WEBAUTHN_ALG_RS256, type: 'public-key' }
        ],
        excludeCredentials: [],
        authenticatorSelection: {
            requireResidentKey: true,
            userVerification: 'required'
        }
    };

    const credential = await navigator.credentials.create({
        publicKey: passkeyCreationOptions
    });

    console.log('Got credential:', credential);

    const clientDataJSON = new TextDecoder('utf-8').decode(credential.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON);

    const passkeyData = {
        userId,
        clientData,
        // Firefox returns nonsense for getPublicKey(), so we can't avoid parsing the attestationObject server-side...
        attestationObject: toBase64(credential.response.attestationObject),
        transports: credential.response.getTransports()
    };
    console.log('Passkey data is', passkeyData);

    return passkeyData;
}
