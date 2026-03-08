/** @type {import('next').NextConfig} */

// WSTG-CONF-06: Remove X-Powered-By header to prevent framework fingerprinting
// Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  // WSTG-CONF-07: HTTP Strict Transport Security (HSTS)
  // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.md
  // WSTG-CONF-12: Content Security Policy (CSP)
  // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy.md
  // WSTG-CONF-14: Other HTTP Security Headers
  // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/14-Test_Other_HTTP_Security_Header_Misconfigurations.md
  // WSTG-CLNT-09: Clickjacking protection via X-Frame-Options
  // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking.md
  // WSTG-CLNT-07: Cross Origin Resource Sharing
  // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing.md
  // WSTG-CONF-08: RIA Cross Domain Policy
  // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy.md
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          // WSTG-CONF-07: HSTS — enforce HTTPS for 1 year, include subdomains
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
          // WSTG-CONF-12: Content Security Policy — restrict resource loading
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
          },
          // WSTG-CONF-14: X-Content-Type-Options — prevent MIME sniffing
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          // WSTG-CONF-14 / WSTG-CLNT-09: X-Frame-Options — prevent clickjacking
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          // WSTG-CONF-14: X-XSS-Protection — legacy XSS filter
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          // WSTG-CONF-14: Referrer-Policy — limit referrer information leakage
          // WSTG-INFO-05: Prevent information leakage via referrer
          // Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage.md
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          // WSTG-CONF-14: Permissions-Policy — restrict browser feature access
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
          },
          // WSTG-CLNT-07 / WSTG-CONF-08: Cross-Origin-Opener-Policy — isolate browsing context
          {
            key: 'Cross-Origin-Opener-Policy',
            value: 'same-origin',
          },
          {
            key: 'Cross-Origin-Resource-Policy',
            value: 'same-origin',
          },
        ],
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: '/ws-api/:path*',
        destination: process.env.NODE_ENV === 'development'
          ? 'http://localhost:8080/:path*'
          : 'http://websocket:8080/:path*',
      },
    ]
  }
};

module.exports = nextConfig;
