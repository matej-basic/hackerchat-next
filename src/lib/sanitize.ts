/**
 * WSTG-INPV-01: Testing for Reflected Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md
 *
 * WSTG-INPV-02: Testing for Stored Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md
 *
 * WSTG-CLNT-01: Testing for DOM-Based Cross Site Scripting
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md
 *
 * WSTG-CLNT-03: Testing for HTML Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection.md
 *
 * WSTG-INPV-05.6: Testing for NoSQL Injection
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.md
 *
 * WSTG-INPV-20: Testing for Mass Assignment
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment.md
 */

/**
 * Encodes HTML entities to prevent XSS attacks.
 * Covers WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT-01, WSTG-CLNT-03
 */
export function sanitizeHtml(input: string): string {
    if (typeof input !== 'string') return '';
    return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

/**
 * Validates that a value is a plain string (not an object/array).
 * Prevents NoSQL operator injection where attackers send { "$gt": "" }
 * instead of a string value.
 * Covers WSTG-INPV-05.6
 */
export function isValidString(value: unknown): value is string {
    return typeof value === 'string';
}

/**
 * Validates username format per WSTG-IDNT-05 (Username Policy)
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy.md
 *
 * Rules:
 * - 3-30 characters long
 * - Alphanumeric, underscores, and hyphens only
 * - Must start with a letter
 */
export function isValidUsername(username: string): { valid: boolean; error?: string } {
    if (username.length < 3) {
        return { valid: false, error: 'Username must be at least 3 characters long' };
    }
    if (username.length > 30) {
        return { valid: false, error: 'Username must not exceed 30 characters' };
    }
    if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(username)) {
        return { valid: false, error: 'Username must start with a letter and contain only letters, numbers, underscores, or hyphens' };
    }
    return { valid: true };
}

/**
 * Validates password strength per WSTG-ATHN-07 (Weak Password Policy)
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Authentication_Methods.md
 *
 * Rules:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one digit
 * - At least one special character
 */
export function isValidPassword(password: string): { valid: boolean; error?: string } {
    if (password.length < 8) {
        return { valid: false, error: 'Password must be at least 8 characters long' };
    }
    if (password.length > 128) {
        return { valid: false, error: 'Password must not exceed 128 characters' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one digit' };
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        return { valid: false, error: 'Password must contain at least one special character' };
    }
    return { valid: true };
}

/**
 * Extracts only allowed fields from a request body.
 * Prevents mass assignment attacks per WSTG-INPV-20.
 */
export function pickAllowedFields<T extends Record<string, unknown>>(
    body: Record<string, unknown>,
    allowedFields: string[]
): Partial<T> {
    const result: Record<string, unknown> = {};
    for (const field of allowedFields) {
        if (field in body) {
            result[field] = body[field];
        }
    }
    return result as Partial<T>;
}
