/**
 * WSTG-ATHN-04: Testing for Bypassing Authentication Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md
 *
 * WSTG-ERRH-01: Testing for Improper Error Handling
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md
 *
 * Security fix: The original code called props.onChange(username) unconditionally
 * after the fetch, regardless of whether login succeeded (HTTP 200) or failed
 * (HTTP 400/401/429/500). This allowed users to appear logged in without existing
 * in the database. Now we check loginResponse.ok before setting the user.
 */

import React, { useState } from 'react';

const LoginForm = (props: { onChange: (arg0: any) => void; }) => {

    const [details, setDetails] = useState({ username: "", password: "" });
    const [error, setError] = useState("");

    const LogIn = async (details: { username: any; password?: string; }) => {
        try {
            setError("");
            const loginResponse = await fetch('/api/auth/signin', {
                method: "POST",
                headers: {
                    'Content-Type': "application/json"
                },
                body: JSON.stringify(details)
            })

            const res = await loginResponse.json()

            // WSTG-ATHN-04: Only set user as authenticated if server confirms success
            if (loginResponse.ok) {
                const { username } = details;
                props.onChange(username)
            } else {
                // Display error from server (generic "Invalid credentials" message)
                setError(res.Result || res.error || "Login failed");
            }
        } catch (err) {
            // WSTG-ERRH-01: Handle network errors gracefully
            setError("Network error. Please try again.");
        }
    }

    const submitHandler = (e: { preventDefault: () => void; }) => {
        e.preventDefault();
        LogIn(details);
    }

    return (
        <div>
            <form className='login-form' onSubmit={submitHandler}>
                {error && <div className='error-message' style={{ color: '#ff4444', marginBottom: '10px', textAlign: 'center' }}>{error}</div>}
                <input type="text" name="username" placeholder="Username" id="username" className="inp" onChange={e => setDetails({ ...details, username: e.target.value })} value={details.username} /> <br />
                <input type="password" name="password" placeholder="Password" id="password" className="inp" onChange={e => setDetails({ ...details, password: e.target.value })} value={details.password} /> <br />
                <input type="submit" value="LOGIN" className='sub-btn' />
            </form>
        </div>
    )
}

export default LoginForm;