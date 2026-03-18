import HackerchatBanner from "../components/HackerchatBanner";
import LoginSignupForm from "../components/LoginSignupForm";
import { useState, useEffect } from 'react';
import Header from "../components/Header";
import GenerateKey from "../services/GenerateKey";
import React from "react";
import ChatView from "../components/ChatView";

export default function Home() {

  const [user, setUser] = useState<string | null>(null);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [websocket, setWebSocket] = useState<WebSocket | null>(null);

  useEffect(() => {
    const currentUserURL = process.env.NEXT_PUBLIC_AUTH_CONNECT + "/api/auth/currentuser";
    fetch(currentUserURL)
      .then(res => res.json())
      .then(data => setUser(data.username))
      .catch(err => console.log(err));
  }, []);

  useEffect(() => {
    const GetKeyPair = async () => {
      const pairOfKeys = await GenerateKey();
      setKeyPair(pairOfKeys);
    };
    GetKeyPair().catch(err => console.log("Error generating key: " + err));
  }, []);

  return (
    <div className="App">
      <HackerchatBanner />
      {(user != null) ? (
        <>
          <Header user={user} onChange={value => { websocket?.close(); setWebSocket(null); setUser(value); }} />
          <ChatView onGetSocket={value => setWebSocket(value)} socket={websocket} user={user} rsaKey={keyPair} />
        </>
      ) : (
        <LoginSignupForm onChange={value => setUser(value)} />
      )}
    </div>
  );
}
