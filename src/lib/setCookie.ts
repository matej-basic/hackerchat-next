/**
 * WSTG-SESS-02: Testing for Cookies Attributes
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.md
 *
 * WSTG-SESS-04: Testing for Exposed Session Variables
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables.md
 *
 * WSTG-SESS-09: Testing for Session Hijacking
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking.md
 *
 * WSTG-CRYP-01: Testing for Weak Transport Layer Security
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security.md
 *
 * WSTG-CRYP-03: Testing for Sensitive Information Sent via Unencrypted Channels
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels.md
 *
 * Cookie security attributes:
 * - HttpOnly: Prevents JavaScript access (XSS cookie theft)
 * - Secure: Only sent over HTTPS (prevents sniffing)
 * - SameSite=Strict: Prevents CSRF attacks
 * - Path=/: Limits cookie scope
 * - Max-Age: Automatic expiration aligned with JWT expiry
 */

import { NextApiResponse } from "next";
// @ts-ignore
import { serialize } from "cookie";

// WSTG-SESS-07: Session timeout — 24 hours in seconds (aligned with JWT expiry)
// Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout.md
const SESSION_MAX_AGE = 24 * 60 * 60; // 24 hours

function setCookie(res: NextApiResponse, name: string, value: string) {
    // WSTG-SESS-02: Set all required cookie security attributes
    const cookieOptions: Record<string, unknown> = {
        httpOnly: true,          // WSTG-SESS-02: Prevent XSS-based cookie theft
        secure: process.env.NODE_ENV === 'production', // WSTG-CRYP-03: HTTPS only in production
        sameSite: 'strict',      // WSTG-SESS-05: CSRF protection via SameSite
        path: '/',               // WSTG-SESS-04: Limit cookie scope
        maxAge: SESSION_MAX_AGE, // WSTG-SESS-07: Automatic session expiry
    };

    res.setHeader('Set-Cookie', serialize(name, value, cookieOptions));
}

/**
 * WSTG-SESS-06: Testing for Logout Functionality
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality.md
 *
 * Properly clears the session cookie with all security attributes
 */
function clearCookie(res: NextApiResponse, name: string) {
    const cookieOptions: Record<string, unknown> = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: 0,  // Immediately expire the cookie
    };

    res.setHeader('Set-Cookie', serialize(name, '', cookieOptions));
}

export { clearCookie };
export default setCookie;