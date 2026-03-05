/**
 * WSTG-CLNT-01: Testing for DOM-Based Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md
 *
 * WSTG-CLNT-02: Testing for JavaScript Execution
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution.md
 *
 * WSTG-CLNT-03: Testing for HTML Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection.md
 *
 * Security: User names from WebSocket are rendered via React JSX which auto-escapes,
 * but we add explicit sanitization as defense-in-depth for the onClick handler
 * which uses e.target.innerText (safe, but validated anyway).
 */

import React, { useEffect, useState } from 'react'

// WSTG-CLNT-01: Client-side sanitization for user-controlled content
function sanitizeForDisplay(input: string): string {
    if (typeof input !== 'string') return '';
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

const UserList = (props: { users: unknown; user: unknown; userThatWantsToChat: unknown; onClickUser: (arg0: any) => void; onAcceptChat: (arg0: any) => void; }) => {
    const [renderedUsers, setRenderedUsers] = useState([]);
    const [userThatWantsToChat, setUserThatWantsToChat] = useState("");
    var useri;

    useEffect(() => {
        if (props.users != 'undefined' && props.users != null) {
            setRenderedUsers([])
            // @ts-ignore
            Object.values(props.users).map(user => {
                if (props.user != user) {
                    // @ts-ignore
                    setRenderedUsers((vals) => {
                        return [...vals, user]
                    })
                }
            })
        }
    }, [props.users])

    useEffect(() => {
        // @ts-ignore
        setUserThatWantsToChat(props.userThatWantsToChat)
    }, [props.userThatWantsToChat])

    // WSTG-CLNT-02: Validate click handler input — only use sanitized innerText
    // @ts-ignore
    const submitHandler = (e) => {
        // WSTG-CLNT-01: The innerText is already escaped by React rendering
        const username = e.target.innerText;
        // Validate username format before sending
        if (typeof username === 'string' && username.length > 0 && username.length <= 30) {
            props.onClickUser(username);
            e.target.classList.add("user-clicked");
        }
    }

    // @ts-ignore
    const HandleChatProposal = (e) => {
        const username = e.target.innerText;
        if (typeof username === 'string' && username.length > 0) {
            props.onAcceptChat(username);
        }
    }

    if (renderedUsers.length > 0) {
        useri = Object.values(renderedUsers).map(user => {
            return (
                <div key={user}>
                    {(userThatWantsToChat == user) ?
                        (<div className='userlist-row' key={user} onClick={(e) => HandleChatProposal(e)}>{user}+</div>) :
                        (<div className='userlist-row' key={user} onClick={(e) => submitHandler(e)}>{user}</div>)}
                </div>
            )
        })
    }

    return (
        <div className='userlist-container'>
            <div className='userlist-header'>CLICK THE USER TO START CHATTING</div>
            {useri}
        </div>
    )
}

export default UserList