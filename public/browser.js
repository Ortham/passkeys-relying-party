export const RP_HOST = 'localhost';

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
    const response = await fetch('/challenge');
    const body = await response.json();

    return toArrayBuffer(body.challenge);
}

export function handlePasskeysNotSupported() {
    console.error('Your web browser does not support passkeys!');
    document.getElementById('errorText').innerText = 'Sign up is not available because your web browser does not appear to support passkeys!';
}
