/**
 * WebSocket relay server for hackerchat-next
 * 
 * Secure WebSocket Implementation:
 * - User registration via JWT session cookie (WSTG-ATHN-04)
 * - User list broadcasting (USERS---[users])
 * - Chat proposals (NEWCHAT;<from>---<to>---<pubkey>)
 * - Chat accepts (CHATACCEPT;<from>---<to>---<pubkey>)
 * - Chat end (CHATEND;<user>)
 * - Encrypted message relay with explicit recipient routing
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env.local') });
const WebSocket = require('ws');
const cookie = require('cookie');
const jwt = require('jsonwebtoken');

const PORT = process.env.WS_PORT || 8080;
const JWT_KEY = process.env.JWT_KEY || ''; // Must have this for secure auth

if (!JWT_KEY) {
    console.error('CRITICAL: JWT_KEY environment variable is not set. Cannot run secure WebSocket server.');
    process.exit(1);
}

const wss = new WebSocket.Server({ port: PORT });

// Track connected users: Map<WebSocket, { username: string }>
const clients = new Map();

console.log(`WebSocket server started on port ${PORT}`);

function broadcastUserList() {
    // Prevent WSTG-INFO-02 leakage: only broadcast unique usernames
    const uniqueUsers = new Set();
    clients.forEach((info) => {
        if (info.username) {
            uniqueUsers.add(info.username);
        }
    });

    const userList = Array.from(uniqueUsers).map(u => JSON.stringify({ username: u }));
    const message = `USERS---[${userList.join(',')}]`;

    clients.forEach((info, ws) => {
        if (ws.readyState === WebSocket.OPEN && info.username) {
            ws.send(message);
        }
    });
}

wss.on('connection', (ws, req) => {
    // WSTG-ATHN-04: Strict Authentication via JWT Cookie
    let username = null;

    try {
        if (req.headers && req.headers.cookie) {
            const cookies = cookie.parse(req.headers.cookie);
            const token = cookies['hackerchat-jwt'];

            if (token) {
                const decoded = jwt.verify(token, JWT_KEY);
                username = decoded.username;
            }
        }
    } catch (e) {
        console.warn('Authentication failed: Invalid token');
    }

    if (!username) {
        console.warn('Rejected unauthenticated WebSocket connection');
        ws.close(1008, 'Authentication required'); // Policy Violation
        return;
    }

    // Assign the securely verified username to this WebSocket
    clients.set(ws, { username });
    console.log(`Client authenticated: ${username}. Total clients: ${clients.size}`);

    // Broadcast updated list automatically
    broadcastUserList();

    ws.on('message', (data) => {
        // Enforce the identity bound to this socket
        const myUsername = clients.get(ws)?.username;
        if (!myUsername) return; // Should not happen

        const message = data.toString();

        // Prevent legacy unauthenticated registration
        if (message.startsWith('USERNAME: ')) {
            console.warn(`User ${myUsername} attempted legacy USERNAME override. Ignoring.`);
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

                // WSTG-BUSL-02: Identity spoofing prevention
                if (sender !== myUsername) {
                    console.warn(`Spoofing attempt: ${myUsername} tried to send proposal as ${sender}`);
                    return;
                }

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

                // WSTG-BUSL-02: Prevent accepting a chat on behalf of someone else
                if (sender !== myUsername) {
                    console.warn(`Spoofing attempt: ${myUsername} tried to accept chat as ${sender}`);
                    return;
                }

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
            const targetUsername = message.substring('CHATEND;'.length);

            clients.forEach((info, client) => {
                // Send the end signal to ALL clients of the person we were chatting with
                // Also send it to OUR OTHER clients, so our whole session ends the chat
                if ((info.username === targetUsername || info.username === myUsername) && client !== ws && client.readyState === WebSocket.OPEN) {
                    client.send(`CHATEND---${myUsername}`);
                }
            });
            return;
        }

        // Handle encrypted chat messages (JSON)
        try {
            const parsed = JSON.parse(message);
            if (parsed.messageAuthor && parsed.messageText && parsed.recipient) {
                // WSTG-BUSL-02: Spoofing protection
                if (parsed.messageAuthor !== myUsername) {
                    console.warn(`Spoofing attempt: ${myUsername} tried to send message as ${parsed.messageAuthor}`);
                    return;
                }

                // Explicit Routing: Only send to the specific recipient and the sender's own clients
                clients.forEach((info, client) => {
                    if ((info.username === parsed.recipient || info.username === myUsername) && client.readyState === WebSocket.OPEN) {
                        client.send(message);
                    }
                });
            } else if (parsed.messageAuthor && !parsed.recipient) {
                console.warn(`Message from ${myUsername} rejected: Missing recipient field.`);
            }
        } catch (e) {
            // Not JSON
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
