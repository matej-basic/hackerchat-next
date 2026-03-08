/**
 * WebSocket relay server for hackerchat-next
 * 
 * Handles:
 * - User registration (USERNAME: <name>)
 * - User list broadcasting (USERS---[users])
 * - Chat proposals (NEWCHAT;<from>---<to>---<pubkey>)
 * - Chat accepts (CHATACCEPT;<from>---<to>---<pubkey>)
 * - Chat end (CHATEND;<user>)
 * - Encrypted message relay (JSON messages)
 */

const WebSocket = require('ws');

const PORT = process.env.WS_PORT || 8080;
const wss = new WebSocket.Server({ port: PORT });

// Track connected users: Map<WebSocket, { username: string }>
const clients = new Map();

console.log(`WebSocket server started on port ${PORT}`);

function broadcastUserList() {
    const userList = [];
    clients.forEach((info) => {
        if (info.username) {
            userList.push(JSON.stringify({ username: info.username }));
        }
    });

    const message = `USERS---[${userList.join(',')}]`;
    clients.forEach((info, ws) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(message);
        }
    });
}

wss.on('connection', (ws) => {
    clients.set(ws, { username: null });
    console.log('Client connected. Total clients:', clients.size);

    ws.on('message', (data) => {
        const message = data.toString();

        // Handle username registration
        if (message.startsWith('USERNAME: ')) {
            const username = message.substring('USERNAME: '.length).trim();
            clients.set(ws, { username });
            console.log(`User registered: ${username}`);
            broadcastUserList();
            return;
        }

        // Handle new chat proposal: NEWCHAT;sender---receiver---pubkey
        if (message.startsWith('NEWCHAT;')) {
            const payload = message.substring('NEWCHAT;'.length);
            const parts = payload.split('---');
            if (parts.length >= 3) {
                const sender = parts[0];
                const receiver = parts[1];
                const pubKey = parts[2];

                // Forward chat proposal to the target user
                clients.forEach((info, client) => {
                    if (info.username === receiver && client.readyState === WebSocket.OPEN) {
                        client.send(`CHATPROPOSAL---${sender}---${pubKey}`);
                    }
                });
            }
            return;
        }

        // Handle chat accept: CHATACCEPT;sender---receiver---pubkey
        if (message.startsWith('CHATACCEPT;')) {
            const payload = message.substring('CHATACCEPT;'.length);
            const parts = payload.split('---');
            if (parts.length >= 3) {
                const sender = parts[0];
                const receiver = parts[1];
                const pubKey = parts[2];

                clients.forEach((info, client) => {
                    if (info.username === receiver && client.readyState === WebSocket.OPEN) {
                        client.send(`CHATACCEPT---${sender}---${pubKey}`);
                    }
                });
            }
            return;
        }

        // Handle chat end: CHATEND;username
        if (message.startsWith('CHATEND;')) {
            const username = message.substring('CHATEND;'.length);

            clients.forEach((info, client) => {
                if (client !== ws && client.readyState === WebSocket.OPEN) {
                    client.send(`CHATEND---${username}`);
                }
            });
            return;
        }

        // Handle encrypted chat messages (JSON)
        try {
            const parsed = JSON.parse(message);
            if (parsed.messageAuthor && parsed.messageText) {
                // Broadcast to all connected clients (including sender so they see their own message)
                clients.forEach((info, client) => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(message);
                    }
                });
            }
        } catch (e) {
            console.warn('Unknown message format:', message.substring(0, 50));
        }
    });

    ws.on('close', () => {
        const info = clients.get(ws);
        console.log(`User disconnected: ${info?.username || 'unknown'}`);
        clients.delete(ws);
        broadcastUserList();
    });

    ws.on('error', (err) => {
        console.error('WebSocket error:', err.message);
    });
});
