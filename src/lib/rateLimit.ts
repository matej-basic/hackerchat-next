/**
 * WSTG-ATHN-03: Testing for Weak Lock Out Mechanism
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism.md
 *
 * WSTG-BUSL-05: Test Number of Times a Function Can Be Used Limits
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits.md
 *
 * WSTG-BUSL-07: Test Defenses Against Application Misuse
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse.md
 *
 * In-memory rate limiter to prevent brute-force attacks.
 * Limits requests per IP address within a configurable time window.
 */

interface RateLimitEntry {
    count: number;
    resetTime: number;
}

const rateLimitStore: Map<string, RateLimitEntry> = new Map();

// Clean up expired entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    rateLimitStore.forEach((entry, key) => {
        if (now > entry.resetTime) {
            rateLimitStore.delete(key);
        }
    });
}, 5 * 60 * 1000);

/**
 * Check if a request should be rate limited.
 *
 * @param identifier - Usually the client IP address
 * @param maxAttempts - Maximum number of requests allowed within the window (default: 5)
 * @param windowMs - Time window in milliseconds (default: 15 minutes)
 * @returns Object with `limited` boolean and `retryAfterMs` remaining wait time
 */
export function checkRateLimit(
    identifier: string,
    maxAttempts: number = 5,
    windowMs: number = 15 * 60 * 1000
): { limited: boolean; retryAfterMs: number; remaining: number } {
    const now = Date.now();
    const entry = rateLimitStore.get(identifier);

    // No existing entry or window expired — allow and create new entry
    if (!entry || now > entry.resetTime) {
        rateLimitStore.set(identifier, {
            count: 1,
            resetTime: now + windowMs,
        });
        return { limited: false, retryAfterMs: 0, remaining: maxAttempts - 1 };
    }

    // Within the window — increment and check
    entry.count += 1;

    if (entry.count > maxAttempts) {
        const retryAfterMs = entry.resetTime - now;
        return { limited: true, retryAfterMs, remaining: 0 };
    }

    return { limited: false, retryAfterMs: 0, remaining: maxAttempts - entry.count };
}

/**
 * Get the client IP address from a Next.js API request.
 *
 * WSTG-INPV-17: Testing for Host Header Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection.md
 */
export function getClientIp(req: { headers: Record<string, string | string[] | undefined>; socket?: { remoteAddress?: string } }): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
        return forwarded.split(',')[0].trim();
    }
    return req.socket?.remoteAddress || 'unknown';
}

// Export for testing
export function _clearRateLimitStore(): void {
    rateLimitStore.clear();
}
