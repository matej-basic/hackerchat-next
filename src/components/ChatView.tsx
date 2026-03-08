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
        const ws = GetWebSocket()
        props.onGetSocket(ws)
        return () => {
            ws.close()
        }
    }, [])

    useEffect(() => {
        setMyRsaKeyPair(props.rsaKey)
    }, [props.rsaKey])

    useEffect(() => {
        // @ts-ignore
        setWebSocket(props.socket)
    }, [props.socket])

    useEffect(() => {
        const fetchExportedKey = async () => {
            // @ts-ignore
            if (!myRsaKeyPair || !myRsaKeyPair.publicKey) return;
            // @ts-ignore
            setExportedPrivateKey(await ExportCryptoKey(myRsaKeyPair))
        }

        fetchExportedKey().catch(err => { console.log("Error exporting private key: ", err) })
    }, [myRsaKeyPair])

    const ProposeChat = async (value: string) => {
        // @ts-ignore
        if (!myRsaKeyPair || !myRsaKeyPair.publicKey) {
            console.error("myRsaKeyPair is missing or has no publicKey");
            return;
        }
        try {
            // @ts-ignore
            const exportedPubKey = await ExportCryptoKey(myRsaKeyPair);
            // @ts-ignore
            websocket.send("NEWCHAT;" + props.user + "---" + value + "---" + JSON.stringify(exportedPubKey));
        } catch (err) {
            console.error("ProposeChat export error:", err);
        }
    }

    const HandleChatProposal = async (value: React.SetStateAction<string>, exportedKey: string) => {
        setUserThatWantsToChat(value);
        try {
            const senderPublicKey = await ImportCryptoKey(JSON.parse(exportedKey))
            // @ts-ignore
            setImportedKey(senderPublicKey)
        } catch (err) {
            console.error("Error importing proposed key:", err);
        }
    }

    const HandleChatAccept = async (value: React.SetStateAction<string>, pubKey: string | null) => {
        // @ts-ignore
        if (!myRsaKeyPair || !myRsaKeyPair.privateKey || !myRsaKeyPair.publicKey) {
            console.error("myRsaKeyPair is missing keys during HandleChatAccept");
            return;
        }
        if (pubKey != null) {
            try {
                const returnedImportedKey = await ImportCryptoKey(JSON.parse(pubKey))
                // @ts-ignore
                setImportedKey(returnedImportedKey)
                // @ts-ignore
                const returnedDerivedKey = await DeriveCryptoKey(returnedImportedKey, myRsaKeyPair.privateKey)
                // @ts-ignore
                setDerivedKey(returnedDerivedKey)
                setUserChat(value)
            } catch (err) {
                console.error("Error during HandleChatAccept derived key setup:", err);
            }
        } else {
            try {
                // @ts-ignore
                const exportedPubKey = await ExportCryptoKey(myRsaKeyPair);
                // @ts-ignore
                websocket.send("CHATACCEPT;" + props.user + "---" + value + "---" + JSON.stringify(exportedPubKey))
                // @ts-ignore
                const returnedDerivedKey = await DeriveCryptoKey(importedKey, myRsaKeyPair.privateKey)
                // @ts-ignore
                setDerivedKey(returnedDerivedKey)
                setUserChat(value)
            } catch (err) {
                console.error("HandleChatAccept export error:", err);
            }
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