import React, { useState } from 'react';

const SignupForm = props => {
    const [details, setDetails] = useState({ username: "", password: "" })

    const SignUp = async (details) => {
        const signupResponse = await fetch('/api/auth/signup', {
            method: "POST",
            headers: {
                'Content-Type': "application/json"
            },
            body: JSON.stringify(details)
        })

        const res = await signupResponse.json()
        const { username } = details;
        props.onChange(username)
    }

    const submitHandler = e => {
        e.preventDefault();
        SignUp(details);
    }

    return (
        <div>
            <form className='login-form' onSubmit={submitHandler}>
                <input type="text" name="username" placeholder="Username" id="username" className="inp" onChange={e => setDetails({ ...details, username: e.target.value })} value={details.username} /> <br />
                <input type="password" name="password" placeholder="Password" id="password" className="inp" onChange={e => setDetails({ ...details, password: e.target.value })} value={details.password} /> <br />
                <input type="submit" value="SIGN UP" className='sub-btn' />
            </form>
        </div>
    )
}

export default SignupForm