const { webcrypto } = require('crypto');
const WebSocket = require('ws');

async function startBot() {
    const keyPair = await webcrypto.subtle.generateKey({
        name: "ECDH",
        namedCurve: "P-384"
    }, true, ["deriveKey", "deriveBits"]);

    const rawPubKey = await webcrypto.subtle.exportKey("raw", keyPair.publicKey);
    const pubKeyArray = Array.from(new Uint8Array(rawPubKey));

    const ws = new WebSocket('ws://localhost:8080');

    ws.on('open', () => {
        ws.send('USERNAME: testerBot');
        console.log('testerBot connected and registered');
    });

    ws.on('message', (data) => {
        const msg = data.toString();
        // Ignore noisy USERS--- broadcast to keep logs clean
        if (!msg.startsWith('USERS---')) {
            console.log('testerBot received:', msg.substring(0, 100));
        }
        if (msg.startsWith('CHATPROPOSAL---')) {
            const parts = msg.split('---');
            const sender = parts[1];
            console.log(`testerBot received CHATPROPOSAL from ${sender}. Accepting...`);
            ws.send(`CHATACCEPT;testerBot---${sender}---${JSON.stringify(pubKeyArray)}`);
        }
    });
}
startBot();
