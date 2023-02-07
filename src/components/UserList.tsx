import React, { useEffect, useState } from 'react'

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

    // @ts-ignore
    const submitHandler = (e) => {
        props.onClickUser(e.target.innerText)
        e.target.classList.add("user-clicked")
    }

    // @ts-ignore
    const HandleChatProposal = (e) => {
        props.onAcceptChat(e.target.innerText)
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