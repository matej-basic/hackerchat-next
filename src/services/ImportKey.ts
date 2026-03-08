// @ts-ignore
async function ImportCryptoKey(publicKeyArray) {
    const rawBuffer = new Uint8Array(publicKeyArray).buffer;
    const importedKey = await window.crypto.subtle.importKey("raw", rawBuffer, {
        name: "ECDH",
        namedCurve: "P-384"
    }, true, [])
    return importedKey
}

export default ImportCryptoKey;