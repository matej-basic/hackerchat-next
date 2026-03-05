/**
 * Comprehensive Security Tests for hackerchat-next
 * Tests OWASP WSTG controls implementation
 */

import { createMocks } from 'node-mocks-http';
import type { NextApiRequest, NextApiResponse } from 'next';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------
const mockSave = jest.fn().mockResolvedValue(undefined);

jest.mock('../../models/user', () => {
    function MockUser(this: any, attrs: any) {
        this.id = 'mock-user-id-123';
        this.username = attrs.username;
        this.email = attrs.username;
        this.password = attrs.password;
        this.save = mockSave;
    }
    MockUser.findOne = jest.fn();
    MockUser.prototype.save = mockSave;
    return { User: MockUser };
});

jest.mock('../../lib/dbConnect', () => jest.fn().mockResolvedValue(undefined));

jest.mock('../../services/password', () => ({
    Password: {
        toHash: jest.fn().mockResolvedValue('mockedhash.mockedsalt'),
        compare: jest.fn(),
    },
}));

jest.mock('../../lib/setCookie', () => ({
    __esModule: true,
    default: jest.fn(),
    clearCookie: jest.fn(),
}));

jest.mock('jsonwebtoken', () => ({
    sign: jest.fn().mockReturnValue('mock-jwt-token'),
    verify: jest.fn().mockReturnValue({ id: 'mock-user-id-123', username: 'testuser' }),
}));

import { User } from '../../models/user';
import { Password } from '../../services/password';
import jwt from 'jsonwebtoken';
import { _clearRateLimitStore } from '../../lib/rateLimit';

import signupHandler from '../../pages/api/auth/signup';
import signinHandler from '../../pages/api/auth/signin';
import signoutHandler from '../../pages/api/auth/signout';
import currentuserHandler from '../../pages/api/auth/currentuser';

// Helper
function createMockReqRes(options: {
    method?: string;
    body?: Record<string, unknown>;
    cookies?: Record<string, string>;
    headers?: Record<string, string>;
}) {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: (options.method || 'POST') as any,
        body: options.body || {},
        cookies: options.cookies || {},
        headers: options.headers || {},
    });
    return { req, res };
}

function getResData(res: any): any {
    const data = res._getData();
    if (typeof data === 'string') {
        try { return JSON.parse(data); } catch { return data; }
    }
    return data;
}

// ============================================================================
// BASELINE FUNCTIONAL TESTS
// ============================================================================
describe('Baseline Functional Tests', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signup: should create a new user with valid credentials', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'newuser', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
    });

    test('signup: should reject duplicate username', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({ username: 'existinguser' });
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'existinguser', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
    });

    test('signin: should sign in with valid credentials', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 'mock-user-id-123',
            username: 'testuser',
            password: 'hashedpassword.salt',
        });
        (Password.compare as jest.Mock).mockResolvedValue(true);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
        expect(getResData(res).Result).toBe('Sign in successful');
    });

    test('signin: should reject invalid username', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'nonexistent', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
    });

    test('signin: should reject wrong password', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 'mock-user-id-123',
            password: 'hashedpassword.salt',
        });
        (Password.compare as jest.Mock).mockResolvedValue(false);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'WrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
    });

    test('signout: should return success', () => {
        const { req, res } = createMockReqRes({ method: 'POST' });
        signoutHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
        expect(getResData(res).Result).toBe('Log out successful');
    });

    test('currentuser: should return null when no JWT cookie', async () => {
        const { req, res } = createMockReqRes({ method: 'GET', cookies: {} });
        await currentuserHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
        expect(getResData(res).username).toBeNull();
    });

    test('currentuser: should return username with valid JWT', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({ username: 'testuser' });
        const { req, res } = createMockReqRes({
            method: 'GET',
            cookies: { 'hackerchat-jwt': 'valid-jwt-token' },
        });
        await currentuserHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
        expect(getResData(res).username).toBe('testuser');
    });
});

// ============================================================================
// WSTG-CONF-06: HTTP Method Enforcement Tests
// ============================================================================
describe('WSTG-CONF-06: HTTP Method Enforcement', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signup: should reject GET requests with 405', async () => {
        const { req, res } = createMockReqRes({ method: 'GET', body: {} });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(405);
        expect(res.getHeader('Allow')).toBe('POST');
    });

    test('signin: should reject GET requests with 405', async () => {
        const { req, res } = createMockReqRes({ method: 'GET', body: {} });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(405);
    });

    test('signin: should reject PUT requests with 405', async () => {
        const { req, res } = createMockReqRes({ method: 'PUT', body: {} });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(405);
    });

    test('signin: should reject DELETE requests with 405', async () => {
        const { req, res } = createMockReqRes({ method: 'DELETE', body: {} });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(405);
    });

    test('signout: should reject GET requests with 405', () => {
        const { req, res } = createMockReqRes({ method: 'GET', body: {} });
        signoutHandler(req, res);
        expect(res._getStatusCode()).toBe(405);
    });

    test('currentuser: should reject DELETE requests with 405', async () => {
        const { req, res } = createMockReqRes({ method: 'DELETE', body: {} });
        await currentuserHandler(req, res);
        expect(res._getStatusCode()).toBe(405);
    });
});

// ============================================================================
// WSTG-IDNT-04: Account Enumeration Prevention
// ============================================================================
describe('WSTG-IDNT-04: Account Enumeration Prevention', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signup: duplicate username should not reveal username exists', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({ username: 'existinguser' });
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'existinguser', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        const data = getResData(res);
        // Should NOT say "Username already taken" — that enables enumeration
        expect(data.error).not.toContain('already taken');
        expect(data.error).toContain('Registration failed');
    });

    test('signin: invalid username uses generic error message', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'nonexistent', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        const data = getResData(res);
        expect(data.Result).toBe('Invalid credentials');
    });

    test('signin: wrong password uses same generic error as invalid username', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 'mock-user-id-123',
            password: 'hashedpassword.salt',
        });
        (Password.compare as jest.Mock).mockResolvedValue(false);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'WrongP@ss1' },
        });
        await signinHandler(req, res);
        const data = getResData(res);
        expect(data.Result).toBe('Invalid credentials');
    });
});

// ============================================================================
// WSTG-IDNT-05: Username Policy Tests
// ============================================================================
describe('WSTG-IDNT-05: Username Policy', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('should reject username shorter than 3 chars', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'ab', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('at least 3 characters');
    });

    test('should reject username with special characters', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'user<script>', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
    });

    test('should reject username starting with number', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: '1user', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
    });

    test('should accept valid username', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validUser_01', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
    });
});

// ============================================================================
// WSTG-ATHN-07: Password Policy Tests
// ============================================================================
describe('WSTG-ATHN-07: Password Policy', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('should reject password shorter than 8 chars', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'Sh0rt!' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('at least 8 characters');
    });

    test('should reject password without uppercase', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'nouppercase1!' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('uppercase');
    });

    test('should reject password without digit', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'NoDigits!!' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('digit');
    });

    test('should reject password without special character', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'NoSpecial1A' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('special character');
    });

    test('should accept strong password', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'Str0ngP@ssw0rd!' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
    });
});

// ============================================================================
// WSTG-INPV-05.6: NoSQL Injection Prevention Tests
// ============================================================================
describe('WSTG-INPV-05.6: NoSQL Injection Prevention', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signup: should reject object as username (NoSQL operator injection)', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: { '$gt': '' }, password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('Invalid input');
    });

    test('signin: should reject object as password (NoSQL operator injection)', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: { '$ne': '' } },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
        expect(getResData(res).error).toContain('Invalid input');
    });

    test('signup: should reject array as username', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: ['admin'], password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(400);
    });
});

// ============================================================================
// WSTG-ATHN-03: Rate Limiting / Brute Force Protection Tests
// ============================================================================
describe('WSTG-ATHN-03: Rate Limiting', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signin: should allow up to 5 attempts', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);

        for (let i = 0; i < 5; i++) {
            const { req, res } = createMockReqRes({
                method: 'POST',
                body: { username: 'testuser', password: 'WrongP@ss1' },
                headers: { 'x-forwarded-for': '192.168.1.100' },
            });
            await signinHandler(req, res);
            expect(res._getStatusCode()).toBe(400); // Invalid credentials, not rate limited
        }
    });

    test('signin: should block 6th attempt with 429', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);

        // First 5 attempts
        for (let i = 0; i < 5; i++) {
            const { req, res } = createMockReqRes({
                method: 'POST',
                body: { username: 'testuser', password: 'WrongP@ss1' },
                headers: { 'x-forwarded-for': '192.168.1.200' },
            });
            await signinHandler(req, res);
        }

        // 6th attempt should be rate limited
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'WrongP@ss1' },
            headers: { 'x-forwarded-for': '192.168.1.200' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(429);
        expect(res.getHeader('Retry-After')).toBeDefined();
    });
});

// ============================================================================
// WSTG-ATHN-06: Cache Control Tests
// ============================================================================
describe('WSTG-ATHN-06: Cache Control Headers', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signin: should set no-store cache control', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res.getHeader('Cache-Control')).toContain('no-store');
        expect(res.getHeader('Pragma')).toBe('no-cache');
    });

    test('signup: should set no-store cache control', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res.getHeader('Cache-Control')).toContain('no-store');
    });

    test('signout: should set no-store cache control', () => {
        const { req, res } = createMockReqRes({ method: 'POST' });
        signoutHandler(req, res);
        expect(res.getHeader('Cache-Control')).toContain('no-store');
    });

    test('currentuser: should set no-store cache control', async () => {
        const { req, res } = createMockReqRes({ method: 'GET', cookies: {} });
        await currentuserHandler(req, res);
        expect(res.getHeader('Cache-Control')).toContain('no-store');
    });
});

// ============================================================================
// WSTG-SESS-10: JWT Tests
// ============================================================================
describe('WSTG-SESS-10: JWT Security', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signin: should sign JWT with expiresIn option', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 'mock-user-id-123',
            username: 'testuser',
            password: 'hashedpassword.salt',
        });
        (Password.compare as jest.Mock).mockResolvedValue(true);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(jwt.sign).toHaveBeenCalledWith(
            expect.objectContaining({ username: 'testuser' }),
            expect.any(String),
            expect.objectContaining({ expiresIn: '24h' })
        );
    });

    test('currentuser: should return 401 for expired JWT', async () => {
        (jwt.verify as jest.Mock).mockImplementation(() => {
            const error: any = new Error('jwt expired');
            error.name = 'TokenExpiredError';
            throw error;
        });
        const { req, res } = createMockReqRes({
            method: 'GET',
            cookies: { 'hackerchat-jwt': 'expired-token' },
        });
        await currentuserHandler(req, res);
        expect(res._getStatusCode()).toBe(401);
        expect(getResData(res).error).toContain('expired');
    });

    test('currentuser: should return 401 for tampered JWT', async () => {
        (jwt.verify as jest.Mock).mockImplementation(() => {
            throw new Error('invalid signature');
        });
        const { req, res } = createMockReqRes({
            method: 'GET',
            cookies: { 'hackerchat-jwt': 'tampered-token' },
        });
        await currentuserHandler(req, res);
        expect(res._getStatusCode()).toBe(401);
        expect(getResData(res).error).toContain('Invalid session');
    });
});

// ============================================================================
// WSTG-ERRH-01/02: Error Handling Tests
// ============================================================================
describe('WSTG-ERRH-01/02: Error Handling', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signup: database error should return generic 500', async () => {
        (User.findOne as jest.Mock).mockRejectedValue(new Error('Connection failed'));
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'validuser', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).toBe(500);
        const data = getResData(res);
        // Should NOT contain stack trace or internal error details
        expect(data.error).not.toContain('Connection failed');
        expect(data.error).toContain('internal error');
    });

    test('signin: database error should return generic 500', async () => {
        (User.findOne as jest.Mock).mockRejectedValue(new Error('DB error'));
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'testuser', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(500);
        const data = getResData(res);
        expect(data.error).not.toContain('DB error');
        expect(data.error).toContain('internal error');
    });
});

// ============================================================================
// Sanitize Library Tests
// ============================================================================
describe('Sanitize Library', () => {
    // Import directly
    const { sanitizeHtml, isValidString, isValidUsername, isValidPassword } = require('../../lib/sanitize');

    test('sanitizeHtml should encode HTML entities', () => {
        expect(sanitizeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;');
    });

    test('sanitizeHtml should handle empty string', () => {
        expect(sanitizeHtml('')).toBe('');
    });

    test('sanitizeHtml should return empty for non-string input', () => {
        expect(sanitizeHtml(123 as any)).toBe('');
    });

    test('isValidString should accept strings', () => {
        expect(isValidString('hello')).toBe(true);
    });

    test('isValidString should reject objects', () => {
        expect(isValidString({ '$gt': '' })).toBe(false);
    });

    test('isValidString should reject arrays', () => {
        expect(isValidString(['a'])).toBe(false);
    });

    test('isValidUsername rejects too short', () => {
        expect(isValidUsername('ab').valid).toBe(false);
    });

    test('isValidUsername rejects starting with number', () => {
        expect(isValidUsername('1user').valid).toBe(false);
    });

    test('isValidUsername accepts valid', () => {
        expect(isValidUsername('validUser_01').valid).toBe(true);
    });

    test('isValidPassword rejects weak passwords', () => {
        expect(isValidPassword('short').valid).toBe(false);
        expect(isValidPassword('nouppercase1!').valid).toBe(false);
        expect(isValidPassword('NOLOWERCASE1!').valid).toBe(false);
        expect(isValidPassword('NoDigits!!AA').valid).toBe(false);
        expect(isValidPassword('NoSpecial1Aa').valid).toBe(false);
    });

    test('isValidPassword accepts strong passwords', () => {
        expect(isValidPassword('StrongP@ss1').valid).toBe(true);
    });
});

// ============================================================================
// Rate Limit Library Tests
// ============================================================================
describe('Rate Limit Library', () => {
    const { checkRateLimit, _clearRateLimitStore: clearStore } = require('../../lib/rateLimit');

    beforeEach(() => {
        clearStore();
    });

    test('should allow requests within limit', () => {
        const result = checkRateLimit('test-ip', 3, 60000);
        expect(result.limited).toBe(false);
        expect(result.remaining).toBe(2);
    });

    test('should block requests exceeding limit', () => {
        for (let i = 0; i < 3; i++) {
            checkRateLimit('test-ip-2', 3, 60000);
        }
        const result = checkRateLimit('test-ip-2', 3, 60000);
        expect(result.limited).toBe(true);
        expect(result.retryAfterMs).toBeGreaterThan(0);
    });
});

// ============================================================================
// WSTG-ATHN-04: Login Bypass Regression Tests
// Regression: LoginForm previously called props.onChange() regardless of
// HTTP status, allowing users to appear logged in without valid credentials.
// These tests ensure the server always returns non-200 for failed auth,
// and never sets a JWT cookie on failure.
// ============================================================================
describe('WSTG-ATHN-04: Login Bypass Prevention (Regression)', () => {
    const setCookie = require('../../lib/setCookie').default;

    beforeEach(() => {
        jest.clearAllMocks();
        _clearRateLimitStore();
    });

    test('signin: should return non-200 status for non-existent user', async () => {
        (User.findOne as jest.Mock).mockResolvedValue(null);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'ghostuser', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        // Server MUST return non-200 so client can distinguish failure
        expect(res._getStatusCode()).not.toBe(200);
        expect(res._getStatusCode()).toBe(400);
        // JWT cookie must NOT be set on failed auth
        expect(setCookie).not.toHaveBeenCalled();
    });

    test('signin: should return non-200 status for wrong password', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 'mock-user-id-123',
            username: 'realuser',
            password: 'hashedpassword.salt',
        });
        (Password.compare as jest.Mock).mockResolvedValue(false);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'realuser', password: 'WrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).not.toBe(200);
        expect(res._getStatusCode()).toBe(400);
        // JWT cookie must NOT be set on failed auth
        expect(setCookie).not.toHaveBeenCalled();
    });

    test('signin: should set JWT cookie ONLY on successful auth', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({
            id: 'mock-user-id-123',
            username: 'realuser',
            password: 'hashedpassword.salt',
        });
        (Password.compare as jest.Mock).mockResolvedValue(true);
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'realuser', password: 'StrongP@ss1' },
        });
        await signinHandler(req, res);
        expect(res._getStatusCode()).toBe(200);
        // JWT cookie MUST be set on success
        expect(setCookie).toHaveBeenCalledWith(
            expect.anything(),
            'hackerchat-jwt',
            expect.any(String)
        );
    });

    test('signup: should return non-200 for duplicate username', async () => {
        (User.findOne as jest.Mock).mockResolvedValue({ username: 'takenuser' });
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'takenuser', password: 'StrongP@ss1' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).not.toBe(200);
        // JWT cookie must NOT be set on failed signup
        expect(setCookie).not.toHaveBeenCalled();
    });

    test('signup: should return non-200 for weak password', async () => {
        const { req, res } = createMockReqRes({
            method: 'POST',
            body: { username: 'newuser', password: 'weak' },
        });
        await signupHandler(req, res);
        expect(res._getStatusCode()).not.toBe(200);
        expect(setCookie).not.toHaveBeenCalled();
    });
});
