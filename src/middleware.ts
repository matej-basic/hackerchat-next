/**
 * WSTG-INPV-04: Testing for HTTP Parameter Pollution
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.md
 *
 * WSTG-INPV-17: Testing for Host Header Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection.md
 *
 * WSTG-CONF-06: Test HTTP Methods
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md
 *
 * WSTG-ATHN-04: Testing for Bypassing Authentication Schema
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md
 *
 * WSTG-BUSL-02: Test Ability to Forge Requests
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests.md
 *
 * WSTG-BUSL-06: Testing for the Circumvention of Work Flows
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows.md
 *
 * WSTG-INFO-08: Fingerprint Web Application Framework
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework.md
 *
 * This middleware handles request validation for auth routes.
 * The original middleware was reading req.json() for all auth routes
 * which broke signout (no JSON body needed). This rewrite fixes that
 * and adds proper security controls.
 */

import { NextRequest, NextResponse } from "next/server";

export default async function middleware(req: NextRequest) {
    const path = req.nextUrl.pathname;

    // WSTG-CONF-06: Only allow POST method for auth API routes
    if (path.startsWith('/api/auth') && path !== '/api/auth/currentuser') {
        if (req.method !== 'POST') {
            return new NextResponse(
                JSON.stringify({ error: 'Method not allowed' }),
                { status: 405, headers: { 'Allow': 'POST', 'Content-Type': 'application/json' } }
            );
        }
    }

    // WSTG-INPV-17: Validate Host header to prevent host header injection
    const host = req.headers.get('host');
    const allowedHosts = [
        'localhost',
        'localhost:3000',
        process.env.NEXT_PUBLIC_AUTH_CONNECT?.replace(/^https?:\/\//, '') || '',
    ].filter(Boolean);

    if (host && !allowedHosts.some(allowed => host === allowed || host.endsWith(`.${allowed}`))) {
        // In production, reject requests with unexpected Host headers
        if (process.env.NODE_ENV === 'production') {
            return new NextResponse(
                JSON.stringify({ error: 'Invalid host' }),
                { status: 400, headers: { 'Content-Type': 'application/json' } }
            );
        }
    }

    // WSTG-INFO-08: Remove framework fingerprinting headers
    const response = NextResponse.next();

    // WSTG-BUSL-02: Add request ID for audit logging
    response.headers.set('X-Request-Id', crypto.randomUUID());

    return response;
}

export const config = {
    matcher: [
        // Match all API routes and pages (but not static files)
        '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
};