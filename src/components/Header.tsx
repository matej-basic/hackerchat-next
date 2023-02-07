import React from 'react';

const Header = props => {
    const submitHandler = async () => {
        const signoutResponse = await fetch('/api/auth/signout', {
            method: "POST",
            headers: {
                'Content-Type': "application/json"
            },
            body: JSON.stringify({ username: "", password: "" })
        })

        const res = await signoutResponse.json()
        props.onChange(null)
    }

    return (
        <div className='header-container'>
            <div className='hello-button'>SIGNED IN AS: {props.user}</div>
            <div className='sign-out-button' onClick={() => submitHandler()}>SIGN OUT</div>
        </div>
    )
}

export default Header;