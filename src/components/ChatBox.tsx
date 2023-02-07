import React, { useEffect, useRef, useState } from 'react'
import GetWebSocket from '../services/GetWebSocket';
import DecryptMessage from '../services/DecryptMessage';

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
            //websocket.send("GET USERLIST")
        }
        // @ts-ignore
        websocket.onmessage = async function (ev: { data: string | null; }) {
            if (ev.data != null) {
                if ((/^USERS---/.test(ev.data.toString()))) {
                    userArray = ev.data.toString().split('---')
                    userArray.splice(0, 1)
                    userArray[0] = userArray[0].split("[")[1]
                    userArray[userArray.length - 1] = userArray[userArray.length - 1].split("]")[0]
                    usersString = userArray.toString()
                    arrayOfUsers = usersString.split(",")
                    Object.values(arrayOfUsers).map(user => {
                        try {
                            var jsonUser = JSON.parse(user)
                            returnValue.push(jsonUser.username)
                        } catch (error) {
                            console.log("Error pushing to array")
                        }
                    })
                    props.onUserListChange(returnValue)
                } else if ((/^CHATPROPOSAL---/.test(ev.data.toString()))) {
                    var userThatWantsToChat = ev.data.toString().split('---')[1]
                    var exportedPrivateKey = ev.data.toString().split('---')[2]
                    props.onUserChatProposal(userThatWantsToChat, exportedPrivateKey)
                } else if ((/^CHATACCEPT---/.test(ev.data.toString()))) {
                    var userThatWantsToChat = ev.data.toString().split('---')[1]
                    var senderPublicKey = ev.data.toString().split('---')[2]
                    props.onUserChatAccept(userThatWantsToChat, senderPublicKey)
                } else if ((/^CHATEND---/.test(ev.data.toString()))) {
                    props.onChatEnd()
                }
                else {
                    const newMessage = JSON.parse(ev.data)
                    const decryptedMessage = await DecryptMessage(newMessage.messageText, newMessage.messageIV, props.derivedKey)
                    // @ts-ignore
                    setMessages((vals) => {
                        return [
                            ...vals, { messageAuthor: newMessage.messageAuthor, messageText: decryptedMessage, messageId: newMessage.messageId }
                        ];
                    });
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