// @ts-ignore
async function DeriveCryptoKey(publicKeyObj, privateKeyObj) {
    const derivedKey = await window.crypto.subtle.deriveKey({
        name: "ECDH",
        public: publicKeyObj
    }, privateKeyObj, {
        name: "AES-GCM",
        length: 256
    }, true, ["encrypt", "decrypt"])

    return derivedKey;
}

export default DeriveCryptoKey;