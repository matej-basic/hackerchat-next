import HackerchatBanner from "../components/HackerchatBanner";
import LoginSignupForm from "../components/LoginSignupForm";
import { useState, useEffect } from 'react';
import Header from "../components/Header";
import GenerateKey from "../services/GenerateKey";
import React from "react";
import ChatView from "../components/ChatView";
import GetWebSocket from "../services/GetWebSocket";
import axios from 'axios'

export default function Home() {

  const [user, setUser] = useState(null);
  const [keyPair, setKeyPair] = useState(null);
  const [websocket, setWebSocket] = useState(null)

  const GetCurrentUser = async () => {
    useEffect(() => {
      const currentUserURL = process.env.NEXT_PUBLIC_AUTH_CONNECT + "/api/auth/currentuser"
      axios.post(currentUserURL, { username: "", password: "" })
        .then(res => {
          const { username } = res.data
          setUser(username);
        }).catch(err => {
          console.log(err);
        })
    }, []);
  }

  useEffect(() => {
    const GetKeyPair = async () => {
      const pairOfKeys = await GenerateKey()
      // @ts-ignore
      setKeyPair(pairOfKeys)
    }

    GetKeyPair()
      .catch(err => { console.log("Error generating key: " + err) })
  })

  GetCurrentUser();

  return (
    <div className="App">
      <HackerchatBanner />
      {/* 
                        // @ts-ignore */}
      {(user != null) ? (<><Header user={user} onChange={value => { websocket.close(); setWebSocket(null); setUser(value) }} /><ChatView onGetSocket={value => setWebSocket(value)} socket={websocket} user={user} rsaKey={keyPair} /></>) : (<LoginSignupForm onChange={value => setUser(value)} />)}
    </div>
  )
}
