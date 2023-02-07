import React from 'react';

const Header = (props: { onChange: (arg0: null) => void; user: string | number | boolean | React.ReactElement<any, string | React.JSXElementConstructor<any>> | React.ReactFragment | React.ReactPortal | null | undefined; }) => {
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