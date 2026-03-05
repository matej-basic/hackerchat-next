/**
 * WSTG-SESS-06: Testing for Logout Functionality
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality.md
 *
 * WSTG-ATHN-06: Testing for Browser Cache Weaknesses
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses.md
 *
 * WSTG-INPV-03: Testing for HTTP Verb Tampering
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering.md
 *
 * WSTG-CONF-06: Test HTTP Methods
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md
 *
 * Proper logout implementation:
 * - Clears the JWT cookie with full security attributes
 * - Sets cache-control headers to prevent caching of logout response
 * - Enforces POST-only method
 */

import { NextApiRequest, NextApiResponse } from "next";
import { clearCookie } from "../../../lib/setCookie";

export default function signoutHandler(req: NextApiRequest, res: NextApiResponse) {
    // WSTG-INPV-03 / WSTG-CONF-06: Enforce POST-only method
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }

    // WSTG-ATHN-06: Prevent browser caching of logout response
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    // WSTG-SESS-06: Properly clear the session cookie with all security attributes
    clearCookie(res, "hackerchat-jwt");

    res.status(200).json({ Result: "Log out successful" });
}