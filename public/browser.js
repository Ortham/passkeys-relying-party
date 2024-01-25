const RP_NAME = 'Passkeys Demo';
const RP_HOST = 'localhost';
const ORIGIN = `http://${RP_HOST}:8080`;

const WEBAUTHN_ALG_ES256 = -7;
const WEBAUTHN_ALG_RS256 = -257;

async function arePasskeysSupported() {
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

function toArrayBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function toBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

async function getChallenge() {
    let response = await fetch('/challenge');
    let body = await response.json();

    return toArrayBuffer(body.challenge);
}

function handlePasskeysNotSupported() {
    console.error('Your web browser does not support passkeys!');
    document.getElementById('errorText').innerText = 'Sign up is not available because your web browser does not appear to support passkeys!';
}
