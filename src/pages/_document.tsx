/**
 * WSTG-CLNT-09: Testing for Clickjacking
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking.md
 *
 * WSTG-CLNT-05: Testing for CSS Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection.md
 *
 * WSTG-INFO-02: Fingerprint Web Server
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.md
 *
 * WSTG-INFO-03: Review Webserver Metafiles for Information Leakage
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage.md
 *
 * Security:
 * - Meta tag for IE compatibility to prevent legacy rendering issues
 * - Clickjacking defense is primarily handled via X-Frame-Options: DENY header in next.config.js
 * - No meta generator tag to prevent framework fingerprinting
 */

import { Html, Head, Main, NextScript } from 'next/document'

export default function Document() {
  return (
    <Html lang="en">
      <Head>
        {/* WSTG-INFO-02: No meta generator tag — prevent framework fingerprinting */}
        {/* WSTG-CLNT-09: Primary clickjacking defense via X-Frame-Options header in next.config.js */}
        {/* WSTG-CONF-14: Ensure proper rendering mode */}
        <meta httpEquiv="X-UA-Compatible" content="IE=edge" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  )
}
