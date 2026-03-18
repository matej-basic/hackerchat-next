import React, { useState, useEffect } from 'react';
import RandomID from '../services/RandomID';
import EncryptMessage from '../services/EncryptMessage';

const ab2str = (buf: ArrayBuffer | Uint8Array): string => {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    return String.fromCharCode.apply(null, Array.from(bytes));
}

const SendMessage = (props: { socket: WebSocket | null; derivedKey: CryptoKey; user: string; onCloseClick: () => void }) => {
    const [messageText, setMessageText] = useState("");
    const [websocket, setWebSocket] = useState<WebSocket | null>(null);

    useEffect(() => {
        setWebSocket(props.socket);
    }, [props.socket]);

    const MessageHandler = async (e: React.FormEvent) => {
        e.preventDefault();
        if (messageText.length > 0 && websocket) {
            const { cipherText, iv } = await EncryptMessage(messageText, props.derivedKey)
            const messageObject = { messageAuthor: props.user, messageText: ab2str(cipherText), messageID: RandomID(), messageIV: ab2str(iv) }
            websocket.send(JSON.stringify(messageObject, null, 0));
            setMessageText("");
        }
    }

    return (
        <div>
            <form className='message-form' onSubmit={MessageHandler} autoComplete="off">
                <input type="text" name="message" placeholder="Your message..." className="send-message" onChange={e => setMessageText(e.target.value)} value={messageText}></input>
            </form>
            <div onClick={() => props.onCloseClick()} className='finish-chat'>CLOSE CHAT</div>
        </div>
    )
}

export default SendMessage
