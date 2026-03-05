/**
 * WSTG-CLNT-10: Testing WebSockets
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets.md
 *
 * WSTG-CLNT-01: Testing for DOM-Based Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md
 *
 * WSTG-BUSL-01: Test Business Logic Data Validation
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation.md
 *
 * Security notes:
 * - Message text is validated for length before sending
 * - WebSocket messages are encrypted with E2E encryption (AES-GCM)
 * - No user-controlled content is rendered unsafely (React auto-escapes JSX)
 */

import React, { useState, useEffect } from 'react';
import RandomID from '../services/RandomID';
import EncryptMessage from '../services/EncryptMessage';
import DecryptMessage from '../services/DecryptMessage';

// WSTG-BUSL-01: Maximum message length to prevent abuse
const MAX_MESSAGE_LENGTH = 5000;

// @ts-ignore
const SendMessage = props => {
    const [messageText, setMessageText] = useState("");
    const [websocket, setWebSocket] = useState(null);

    const InitWebSocket = () => {
        useEffect(() => {
            setWebSocket(props.socket);
        }, [])
    };

    InitWebSocket();

    // @ts-ignore
    const ab2str = (bufer) => {
        // @ts-ignore
        return String.fromCharCode.apply(null, new Uint8Array(bufer));
    }

    // @ts-ignore
    const str2ab = (str) => {
        var buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
        var bufView = new Uint8Array(buf);
        for (var i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    // @ts-ignore
    const MessageHandler = async (e) => {
        e.preventDefault();
        // WSTG-BUSL-01: Validate message content before sending
        if (messageText.length > 0 && messageText.length <= MAX_MESSAGE_LENGTH) {
            const { cipherText, iv } = await EncryptMessage(messageText, props.derivedKey)
            const messageObject = { messageAuthor: props.user, messageText: ab2str(cipherText), messageID: RandomID(), messageIV: ab2str(iv) }
            // @ts-ignore
            websocket.send(JSON.stringify(messageObject, null, 0));
            setMessageText("");
        }
    }

    const HandleClick = () => {
        props.onCloseClick()
    }

    return (
        <div>
            <form className='message-form' onSubmit={MessageHandler} autoComplete="off">
                {/* WSTG-CLNT-01: Input field uses controlled React state — safe from DOM XSS */}
                <input
                    type="text"
                    name="message"
                    placeholder="Your message..."
                    className="send-message"
                    onChange={e => setMessageText(e.target.value)}
                    value={messageText}
                    maxLength={MAX_MESSAGE_LENGTH}
                ></input>
            </form>
            <div onClick={e => { HandleClick() }} className='finish-chat'>CLOSE CHAT</div>
        </div>
    )
}

export default SendMessage