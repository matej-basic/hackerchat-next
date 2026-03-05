/**
 * WSTG-CLNT-01: Testing for DOM-Based Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md
 *
 * WSTG-CLNT-03: Testing for HTML Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection.md
 *
 * WSTG-CLNT-10: Testing WebSockets
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets.md
 *
 * WSTG-CLNT-11: Test Web Messaging
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging.md
 *
 * WSTG-CLNT-12: Test Browser Storage
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage.md
 *
 * WSTG-INPV-01: Testing for Reflected Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md
 *
 * WSTG-INPV-02: Testing for Stored Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md
 *
 * Security notes:
 * - React escapes JSX content by default (prevents most XSS)
 * - We add explicit sanitization for WebSocket messages which bypass React rendering
 * - Messages are encrypted end-to-end, but decrypted content must still be sanitized
 * - No sensitive data is stored in localStorage/sessionStorage (WSTG-CLNT-12)
 */

import React, { useEffect, useRef, useState } from 'react'
import GetWebSocket from '../services/GetWebSocket';
import DecryptMessage from '../services/DecryptMessage';

// WSTG-CLNT-01 / WSTG-INPV-01: Client-side HTML entity encoding
// Even though React auto-escapes JSX, we sanitize data from WebSocket
// messages as defense-in-depth since they bypass server-side rendering
function sanitizeForDisplay(input: string): string {
    if (typeof input !== 'string') return '';
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

const ChatBox = (props: { socket: React.SetStateAction<null>; user: string; onUserListChange: (arg0: any[]) => void; onUserChatProposal: (arg0: any, arg1: any) => void; onUserChatAccept: (arg0: any, arg1: any) => void; onChatEnd: () => void; derivedKey: any; }) => {
    const [messages, setMessages] = useState([]);
    const [websocket, setWebSocket] = useState(null);
    const messageRef = useRef(null);
    var renderedMessages;

    var userArray;
    var usersString;
    var arrayOfUsers;
    var returnValue: any[] = []

    useEffect(() => {
        // eslint-disable-next-line
        setWebSocket(props.socket);
        // eslint-disable-next-line
    }, []);

    const str2ab = (str: string) => {
        var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
        var bufView = new Uint8Array(buf);
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    useEffect(() => {
        if (messageRef) {
            // @ts-ignore: Object is possibly 'null'.
            messageRef.current.addEventListener('DOMNodeInserted', (event: { currentTarget: any; }) => {
                const { currentTarget: target } = event;
                target.scroll({ top: target.scrollHeight, behavior: 'smooth' });
            })
        }
    }, []);

    if (websocket) {
        // @ts-ignore
        websocket.onopen = function (ev: any) {
            // @ts-ignore
            websocket.send("USERNAME: " + props.user)
        }
        // @ts-ignore
        websocket.onmessage = async function (ev: { data: string | null; }) {
            if (ev.data != null) {
                // WSTG-CLNT-10: Validate WebSocket message format before processing
                // Only process messages that match expected patterns
                const messageStr = ev.data.toString();

                if ((/^USERS---/.test(messageStr))) {
                    userArray = messageStr.split('---')
                    userArray.splice(0, 1)
                    userArray[0] = userArray[0].split("[")[1]
                    userArray[userArray.length - 1] = userArray[userArray.length - 1].split("]")[0]
                    usersString = userArray.toString()
                    arrayOfUsers = usersString.split(",")
                    Object.values(arrayOfUsers).map(user => {
                        try {
                            var jsonUser = JSON.parse(user)
                            // WSTG-CLNT-01: Sanitize username from WebSocket before display
                            returnValue.push(sanitizeForDisplay(jsonUser.username))
                        } catch (error) {
                            console.log("Error pushing to array")
                        }
                    })
                    props.onUserListChange(returnValue)
                } else if ((/^CHATPROPOSAL---/.test(messageStr))) {
                    // WSTG-CLNT-10: Validate chat proposal format
                    var parts = messageStr.split('---');
                    if (parts.length >= 3) {
                        var userThatWantsToChat = sanitizeForDisplay(parts[1]);
                        var exportedPrivateKey = parts[2];
                        props.onUserChatProposal(userThatWantsToChat, exportedPrivateKey)
                    }
                } else if ((/^CHATACCEPT---/.test(messageStr))) {
                    var parts = messageStr.split('---');
                    if (parts.length >= 3) {
                        var userThatWantsToChat = sanitizeForDisplay(parts[1]);
                        var senderPublicKey = parts[2];
                        props.onUserChatAccept(userThatWantsToChat, senderPublicKey)
                    }
                } else if ((/^CHATEND---/.test(messageStr))) {
                    props.onChatEnd()
                }
                else {
                    // WSTG-CLNT-10: Validate JSON format before parsing
                    try {
                        const newMessage = JSON.parse(messageStr);

                        // WSTG-BUSL-03: Integrity check — verify message has required fields
                        // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks.md
                        if (!newMessage.messageText || !newMessage.messageIV || !newMessage.messageAuthor) {
                            console.warn('Received malformed message, skipping');
                            return;
                        }

                        const decryptedMessage = await DecryptMessage(newMessage.messageText, newMessage.messageIV, props.derivedKey)

                        // WSTG-CLNT-01 / WSTG-INPV-02: Sanitize decrypted message content
                        // Even with E2E encryption, sanitize to prevent XSS from malicious clients
                        const safeMessage = sanitizeForDisplay(decryptedMessage as string);
                        const safeAuthor = sanitizeForDisplay(newMessage.messageAuthor);

                        // @ts-ignore
                        setMessages((vals) => {
                            return [
                                ...vals, { messageAuthor: safeAuthor, messageText: safeMessage, messageId: newMessage.messageId }
                            ];
                        });
                    } catch (parseError) {
                        // WSTG-ERRH-01: Don't crash on malformed messages
                        console.warn('Failed to parse WebSocket message');
                    }
                }
            }
        }
    }

    if (messages.length > 0) {
        renderedMessages = Object.values(messages).map(message => {
            // @ts-ignore
            return (message.messageAuthor === props.user) ? (
                // @ts-ignore
                <div className='message-row-mine'><div className='message-mine' key={message.messageId}>{message.messageText}</div></div>) : (
                // @ts-ignore
                <div className='message-row'><div className='message' key={message.messageId}><div className='message-author'>{message.messageAuthor}</div>{message.messageText}</div></div>)
        });
    }

    return (
        <div className='chat-container'>
            <div className='chat-box' ref={messageRef}>
                {renderedMessages}
            </div>
        </div>
    )
}

export default ChatBox