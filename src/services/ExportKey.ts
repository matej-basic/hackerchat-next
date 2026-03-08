// @ts-ignore
async function ExportCryptoKey(keyPair) {
    const publicKeyBuffer = await window.crypto.subtle.exportKey("raw", keyPair.publicKey)
    // Convert ArrayBuffer to Array for JSON transmission
    return Array.from(new Uint8Array(publicKeyBuffer));
}

export default ExportCryptoKey;