/**
 * WSTG-IDNT-02: Test User Registration Process
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process.md
 *
 * WSTG-IDNT-04: Testing for Account Enumeration and Guessable User Account
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.md
 *
 * WSTG-IDNT-05: Testing for Weak or Unenforced Username Policy
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy.md
 *
 * WSTG-ATHN-04: Testing for Bypassing Authentication Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md
 *
 * WSTG-ATHN-06: Testing for Browser Cache Weaknesses
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses.md
 *
 * WSTG-ATHN-07: Testing for Weak Password Policy
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Authentication_Methods.md
 *
 * WSTG-INPV-03: Testing for HTTP Verb Tampering
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering.md
 *
 * WSTG-INPV-05.6: Testing for NoSQL Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.md
 *
 * WSTG-INPV-20: Testing for Mass Assignment
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment.md
 *
 * WSTG-ERRH-01: Testing for Improper Error Handling
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md
 *
 * WSTG-ERRH-02: Testing for Stack Traces
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces.md
 *
 * WSTG-BUSL-01: Test Business Logic Data Validation
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation.md
 *
 * WSTG-BUSL-05: Test Number of Times a Function Can Be Used Limits
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits.md
 *
 * WSTG-SESS-10: Testing JSON Web Tokens
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens.md
 *
 * WSTG-SESS-03: Testing for Session Fixation
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation.md
 */

import type { NextApiRequest, NextApiResponse } from 'next';
import { User } from '../../../models/user';
import dbConnect from '../../../lib/dbConnect';
import jwt from 'jsonwebtoken';
import setCookie from '../../../lib/setCookie';
import { isValidString, isValidUsername, isValidPassword, sanitizeHtml } from '../../../lib/sanitize';
import { checkRateLimit, getClientIp } from '../../../lib/rateLimit';

export default async function signupHandler(req: NextApiRequest, res: NextApiResponse) {
    // WSTG-INPV-03 / WSTG-CONF-06: Enforce POST-only method
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }

    // WSTG-ATHN-06: Prevent browser caching of auth responses
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    try {
        // WSTG-BUSL-05: Rate limit signup to prevent mass account creation
        const clientIp = getClientIp(req);
        const rateCheck = checkRateLimit(`signup:${clientIp}`, 10, 15 * 60 * 1000);
        if (rateCheck.limited) {
            res.setHeader('Retry-After', Math.ceil(rateCheck.retryAfterMs / 1000).toString());
            res.status(429).json({ error: 'Too many signup attempts. Please try again later.' });
            return;
        }

        // WSTG-INPV-20: Extract only allowed fields (mass assignment prevention)
        const { username, password } = req.body;

        // WSTG-INPV-05.6: Validate input types to prevent NoSQL operator injection
        if (!isValidString(username) || !isValidString(password)) {
            res.status(400).json({ error: 'Invalid input format' });
            return;
        }

        // WSTG-IDNT-05: Enforce username policy
        const usernameCheck = isValidUsername(username);
        if (!usernameCheck.valid) {
            res.status(400).json({ error: usernameCheck.error });
            return;
        }

        // WSTG-ATHN-07: Enforce strong password policy
        const passwordCheck = isValidPassword(password);
        if (!passwordCheck.valid) {
            res.status(400).json({ error: passwordCheck.error });
            return;
        }

        await dbConnect();

        // WSTG-IDNT-04: Check for existing user but return generic error
        // to prevent account enumeration
        const existingUser = await User.findOne({ username: sanitizeHtml(username) });
        if (existingUser) {
            // WSTG-IDNT-04: Generic error prevents enumeration of valid usernames
            res.status(400).json({ error: 'Registration failed. Please try different credentials.' });
            return;
        }

        const user = new User({ username, password });
        await user.save();

        // WSTG-SESS-10: Sign JWT with expiration
        // WSTG-SESS-03: Issue a new token on registration (prevent session fixation)
        const userJWT = jwt.sign({
            id: user.id,
            username: user.username
        }, process.env.JWT_KEY!, {
            expiresIn: '24h'  // WSTG-SESS-07: Token expiry aligned with session timeout
        });

        setCookie(res, "hackerchat-jwt", userJWT);

        // WSTG-ERRH-02: Don't leak internal user object; return minimal info
        res.status(200).json({ username: user.username });

    } catch (error) {
        // WSTG-ERRH-01 / WSTG-ERRH-02: Generic error response, no stack traces
        console.error('Signup error:', error);
        res.status(500).json({ error: 'An internal error occurred. Please try again later.' });
    }
}