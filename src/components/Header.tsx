/**
 * WSTG-CLNT-04: Testing for Client-side URL Redirect
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect.md
 *
 * WSTG-CLNT-09: Testing for Clickjacking
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking.md
 *
 * WSTG-CLNT-14: Testing for Reverse Tabnabbing
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/14-Testing_for_Reverse_Tabnabbing.md
 *
 * Security notes:
 * - Sign out uses fetch() to POST to signout API, no URL redirection
 * - No external links rendered in this component (no tabnabbing risk)
 * - Clickjacking prevention is handled server-side via X-Frame-Options: DENY header
 * - Uses onClick handler (not <a> tags) — no open redirect vulnerability
 */

import React from 'react';

const Header = (props: { onChange: (arg0: null) => void; user: string | number | boolean | React.ReactElement<any, string | React.JSXElementConstructor<any>> | React.ReactFragment | React.ReactPortal | null | undefined; }) => {
    const submitHandler = async () => {
        // WSTG-SESS-06: Proper logout via POST request
        // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality.md
        try {
            const signoutResponse = await fetch('/api/auth/signout', {
                method: "POST",
                headers: {
                    'Content-Type': "application/json"
                },
                body: JSON.stringify({})
            })

            if (signoutResponse.ok) {
                props.onChange(null)
            } else {
                // WSTG-ERRH-01: Handle signout failure gracefully
                console.error('Signout failed');
                props.onChange(null) // Still clear client state
            }
        } catch (error) {
            // WSTG-ERRH-01: Handle network errors gracefully
            console.error('Signout error:', error);
            props.onChange(null) // Still clear client state on error
        }
    }

    return (
        <div className='header-container'>
            <div className='hello-button'>SIGNED IN AS: {props.user}</div>
            <div className='sign-out-button' onClick={() => submitHandler()}>SIGN OUT</div>
        </div>
    )
}

export default Header;