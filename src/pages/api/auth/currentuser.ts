/**
 * WSTG-ATHZ-02: Testing for Bypassing Authorization Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.md
 *
 * WSTG-SESS-10: Testing JSON Web Tokens
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens.md
 *
 * WSTG-SESS-01: Testing for Session Management Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema.md
 *
 * WSTG-ERRH-01: Testing for Improper Error Handling
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md
 *
 * WSTG-CONF-06: Test HTTP Methods
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md
 *
 * WSTG-APIT-02: API Broken Object Level Authorization
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization.md
 *
 * WSTG-ATHN-06: Testing for Browser Cache Weaknesses
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses.md
 */

import { NextApiRequest, NextApiResponse } from "next";
import jwt from 'jsonwebtoken';
import dbConnect from "../../../lib/dbConnect";
import { User } from "../../../models/user";

export default async function currentuserHandler(req: NextApiRequest, res: NextApiResponse) {
    // WSTG-CONF-06: Enforce allowed methods only (GET or POST)
    if (req.method !== 'GET' && req.method !== 'POST') {
        res.setHeader('Allow', 'GET, POST');
        res.status(405).json({ error: 'Method not allowed' });
        return;
    }

    // WSTG-ATHN-06: Prevent browser caching of user session data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    try {
        const cookies = req.cookies;
        const token = cookies["hackerchat-jwt"];

        if (token === undefined || token === 'null' || token === '') {
            res.status(200).json({ username: null });
            return;
        }

        // WSTG-SESS-10: Validate JWT token with proper error handling
        // WSTG-ATHZ-02: Verify token signature and expiration to prevent auth bypass
        let decoded: any;
        try {
            decoded = jwt.verify(token, process.env.JWT_KEY!);
        } catch (jwtError: any) {
            // WSTG-SESS-10: Handle expired or tampered tokens
            if (jwtError.name === 'TokenExpiredError') {
                res.status(401).json({ error: 'Session expired. Please sign in again.' });
                return;
            }
            // WSTG-ERRH-01: Generic error for invalid token (don't reveal details)
            res.status(401).json({ error: 'Invalid session. Please sign in again.' });
            return;
        }

        await dbConnect();

        // WSTG-APIT-02: Validate the user still exists in DB (account may have been deleted)
        const user = await User.findOne({ username: decoded.username });
        if (!user) {
            res.status(401).json({ error: 'User not found. Please sign in again.' });
            return;
        }

        res.status(200).json({ username: user.username });

    } catch (error) {
        // WSTG-ERRH-01: Generic error, no stack trace leakage
        console.error('Currentuser error:', error);
        res.status(500).json({ error: 'An internal error occurred.' });
    }
}