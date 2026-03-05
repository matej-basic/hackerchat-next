/**
 * WSTG-ATHN-01: Testing for Credentials Transported over an Encrypted Channel
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel.md
 *
 * WSTG-ATHN-02: Testing for Default Credentials
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials.md
 *
 * WSTG-ATHN-03: Testing for Weak Lock Out Mechanism
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism.md
 *
 * WSTG-ATHN-04: Testing for Bypassing Authentication Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md
 *
 * WSTG-ATHN-06: Testing for Browser Cache Weaknesses
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses.md
 *
 * WSTG-INPV-03: Testing for HTTP Verb Tampering
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering.md
 *
 * WSTG-INPV-05.6: Testing for NoSQL Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.md
 *
 * WSTG-ERRH-01: Testing for Improper Error Handling
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md
 *
 * WSTG-SESS-10: Testing JSON Web Tokens
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens.md
 *
 * WSTG-SESS-03: Testing for Session Fixation
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation.md
 *
 * WSTG-BUSL-02: Test Ability to Forge Requests
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests.md
 */

import { NextApiRequest, NextApiResponse } from "next";
import dbConnect from "../../../lib/dbConnect";
import { User } from "../../../models/user";
import { Password } from "../../../services/password";
import jwt from 'jsonwebtoken';
import setCookie from "../../../lib/setCookie";
import { isValidString } from "../../../lib/sanitize";
import { checkRateLimit, getClientIp } from "../../../lib/rateLimit";

// WSTG-ATHN-02: Validate that JWT_KEY is not a default/weak value
const WEAK_KEYS = ['secret', 'password', 'jwt_secret', 'supersecretkey', 'changeme', 'default'];

export default async function signinHandler(req: NextApiRequest, res: NextApiResponse) {
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
        // WSTG-ATHN-02: Warn if JWT_KEY is a weak/default value
        const jwtKey = process.env.JWT_KEY;
        if (!jwtKey || jwtKey.length < 32 || WEAK_KEYS.some(weak => jwtKey.toLowerCase().includes(weak))) {
            console.warn('SECURITY WARNING: JWT_KEY is weak or uses a default value. Set a strong secret in production!');
        }

        // WSTG-ATHN-03: Rate limit sign-in to prevent brute-force attacks
        const clientIp = getClientIp(req);
        const rateCheck = checkRateLimit(`signin:${clientIp}`, 5, 15 * 60 * 1000);
        if (rateCheck.limited) {
            res.setHeader('Retry-After', Math.ceil(rateCheck.retryAfterMs / 1000).toString());
            res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
            return;
        }

        const { username, password } = req.body;

        // WSTG-INPV-05.6: Validate input types to prevent NoSQL operator injection
        if (!isValidString(username) || !isValidString(password)) {
            res.status(400).json({ error: 'Invalid input format' });
            return;
        }

        await dbConnect();

        const existingUser = await User.findOne({ username });
        if (!existingUser) {
            // WSTG-IDNT-04: Generic error prevents account enumeration
            res.status(400).json({ Result: "Invalid credentials" });
            return;
        }

        const passwordsMatch = await Password.compare(existingUser.password, password);
        if (!passwordsMatch) {
            // WSTG-IDNT-04: Same generic error for wrong password (prevents enumeration)
            res.status(400).json({ Result: "Invalid credentials" });
            return;
        }

        // WSTG-SESS-10: Sign JWT with expiration
        // WSTG-SESS-03: Issue a new token on each login (prevent session fixation)
        const userJWT = jwt.sign({
            id: existingUser.id,
            username: existingUser.username
        }, process.env.JWT_KEY!, {
            expiresIn: '24h'  // WSTG-SESS-07: Token expiry aligned with session timeout
        });

        setCookie(res, "hackerchat-jwt", userJWT);
        res.status(200).json({ Result: "Sign in successful" });

    } catch (error) {
        // WSTG-ERRH-01: Generic error response, no stack traces
        console.error('Signin error:', error);
        res.status(500).json({ error: 'An internal error occurred. Please try again later.' });
    }
}