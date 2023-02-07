import React, { useState, useEffect } from 'react'
import GetWebSocket from '../services/GetWebSocket';
import ChatBox from './ChatBox'
import SendMessage from './SendMessage'
import UserList from './UserList';
import ExportCryptoKey from '../services/ExportKey';
import DeriveCryptoKey from '../services/DeriveKey';
import ImportCryptoKey from '../services/ImportKey';

const ChatView = (props: { onGetSocket: (arg0: WebSocket) => void; rsaKey: React.SetStateAction<null>; socket: unknown; user: string; }) => {
    const [websocket, setWebSocket] = useState(null);
    const [userList, setUserList] = useState([]);
    const [userChat, setUserChat] = useState("");
    const [userThatWantsToChat, setUserThatWantsToChat] = useState("");
    const [importedKey, setImportedKey] = useState(null) // Public key of the other client
    const [derivedKey, setDerivedKey] = useState(null) // Derived key that should be the same on both sides
    const [exportedPrivateKey, setExportedPrivateKey] = useState("") // Exported my own public key
    const [myRsaKeyPair, setMyRsaKeyPair] = useState(null)

    var senderPublicKey;

    useEffect(() => {
        props.onGetSocket(GetWebSocket())
    }, [])

    useEffect(() => {
        setMyRsaKeyPair(props.rsaKey)
    }, [])

    useEffect(() => {
        // @ts-ignore
        setWebSocket(props.socket)
    }, [props.socket])

    useEffect(() => {
        const fetchExportedKey = async () => {
            // @ts-ignore
            setExportedPrivateKey(await window.crypto.subtle.exportKey("jwk", myRsaKeyPair.publicKey))
        }

        fetchExportedKey().catch(err => { console.log("Error exporting private key") })
    }, [])

    const ProposeChat = async (value: string) => {
        // @ts-ignore
        websocket.send("NEWCHAT;" + props.user + "---" + value + "---" + JSON.stringify(await window.crypto.subtle.exportKey("jwk", myRsaKeyPair.publicKey)));
    }

    const HandleChatProposal = async (value: React.SetStateAction<string>, exportedKey: string) => {
        setUserThatWantsToChat(value);
        //const senderPublicKey = await ImportCryptoKey(JSON.parse(exportedKey))
        const senderPublicNotImported = JSON.parse(exportedKey)
        senderPublicKey = JSON.parse(exportedKey)
        setImportedKey(senderPublicKey)
    }

    const HandleChatAccept = async (value: React.SetStateAction<string>, pubKey: string | null) => {
        if (pubKey != null) {
            const returnedImportedKey = await ImportCryptoKey(JSON.parse(pubKey))
            // @ts-ignore
            setImportedKey(returnedImportedKey)
            // @ts-ignore
            const returnedDerivedKey = await DeriveCryptoKey(JSON.parse(pubKey), await window.crypto.subtle.exportKey("jwk", myRsaKeyPair.privateKey))
            // @ts-ignore
            setDerivedKey(returnedDerivedKey)
            setUserChat(value)
        } else {
            // @ts-ignore
            websocket.send("CHATACCEPT;" + props.user + "---" + value + "---" + JSON.stringify(await window.crypto.subtle.exportKey("jwk", myRsaKeyPair.publicKey)))
            // @ts-ignore
            const returnedDerivedKey = await DeriveCryptoKey(importedKey, await window.crypto.subtle.exportKey("jwk", myRsaKeyPair.privateKey))
            // @ts-ignore
            setDerivedKey(returnedDerivedKey)
            setUserChat(value)
        }
    }

    const HandleChatClose = () => {
        setUserChat("")
        setUserThatWantsToChat("")
        // @ts-ignore
        websocket.send("CHATEND;" + props.user)
    }

    if (websocket != null) {
        return (
            <div>
                {(userChat == "") ? (
                    <>
                        {/* 
                    // @ts-ignore */}
                        <UserList onChatEnd={(value: any) => { setUserChat("") }} onAcceptChat={(value: React.SetStateAction<string>) => { HandleChatAccept(value, null) }} onClickUser={(value: string) => { ProposeChat(value); }} user={props.user} users={userList} userThatWantsToChat={userThatWantsToChat} />
                        {/* 
                        // @ts-ignore */}
                        <ChatBox socket={websocket} user={props.user} onUserListChange={value => setUserList(value)} onUserChatProposal={(value, exportedKey) => { HandleChatProposal(value, exportedKey) }} onUserChatAccept={(value, pubKey) => HandleChatAccept(value, pubKey)} />
                    </>
                ) : (
                    <>
                        {/* 
                        // @ts-ignore */}
                        <ChatBox onChatEnd={(value: any) => { HandleChatClose() }} socket={websocket} user={props.user} onUserListChange={value => setUserList(value)} derivedKey={derivedKey} />
                        <SendMessage onCloseClick={() => { HandleChatClose() }} socket={websocket} user={props.user} derivedKey={derivedKey} />
                    </>
                )}
            </div>
        )
    }
}

export default ChatView