/**
 * WSTG-ATHN-04: Testing for Bypassing Authentication Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md
 *
 * WSTG-ERRH-01: Testing for Improper Error Handling
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md
 *
 * Security fix: Same as LoginForm — the original code set the user as registered
 * unconditionally. Now we check signupResponse.ok before setting the user.
 */

import React, { useState } from 'react';

const SignupForm = (props: { onChange: (arg0: any) => void; }) => {
    const [details, setDetails] = useState({ username: "", password: "" })
    const [error, setError] = useState("");

    const SignUp = async (details: { username: any; password?: string; }) => {
        try {
            setError("");
            const signupResponse = await fetch('/api/auth/signup', {
                method: "POST",
                headers: {
                    'Content-Type': "application/json"
                },
                body: JSON.stringify(details)
            })

            const res = await signupResponse.json()

            // WSTG-ATHN-04: Only set user as authenticated if server confirms success
            if (signupResponse.ok) {
                const { username } = details;
                props.onChange(username)
            } else {
                // Display error from server (password policy, username policy, etc.)
                setError(res.error || "Signup failed");
            }
        } catch (err) {
            // WSTG-ERRH-01: Handle network errors gracefully
            setError("Network error. Please try again.");
        }
    }

    // @ts-ignore
    const submitHandler = e => {
        e.preventDefault();
        SignUp(details);
    }

    return (
        <div>
            <form className='login-form' onSubmit={submitHandler}>
                {error && <div className='error-message' style={{ color: '#ff4444', marginBottom: '10px', textAlign: 'center' }}>{error}</div>}
                <input type="text" name="username" placeholder="Username" id="username" className="inp" onChange={e => setDetails({ ...details, username: e.target.value })} value={details.username} /> <br />
                <input type="password" name="password" placeholder="Password" id="password" className="inp" onChange={e => setDetails({ ...details, password: e.target.value })} value={details.password} /> <br />
                <input type="submit" value="SIGN UP" className='sub-btn' />
            </form>
        </div>
    )
}

export default SignupForm