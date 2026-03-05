/**
 * WSTG-CRYP-04: Testing for Weak Encryption
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption.md
 *
 * WSTG-BUSL-04: Test for Process Timing
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing.md
 *
 * Security improvements:
 * - Increased salt length from 8 to 16 bytes for stronger hashing
 * - Uses timing-safe comparison (crypto.timingSafeEqual) to prevent timing attacks
 * - Explicit scrypt key derivation length of 64 bytes
 */

import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(scrypt);

// WSTG-CRYP-04: Use a 16-byte salt (128 bits) for strong randomness
const SALT_LENGTH = 16;
// WSTG-CRYP-04: 64-byte (512 bits) derived key length
const KEY_LENGTH = 64;

export class Password {

    static async toHash(password: string) {
        // WSTG-CRYP-04: Generate a cryptographically secure random salt
        const salt = randomBytes(SALT_LENGTH).toString('hex');
        const buf = (await scryptAsync(password, salt, KEY_LENGTH)) as Buffer;

        return `${buf.toString('hex')}.${salt}`;
    }

    static async compare(storedPassword: string, suppliedPassword: string) {
        const [hashedPassword, salt] = storedPassword.split('.');

        // WSTG-CRYP-04: Derive key from supplied password with same salt
        const buf = (await scryptAsync(suppliedPassword, salt, KEY_LENGTH)) as Buffer;

        // WSTG-BUSL-04 / WSTG-CRYP-04: Use timing-safe comparison to prevent
        // timing attacks that could leak information about the password hash
        const storedBuf = Buffer.from(hashedPassword, 'hex');
        if (buf.length !== storedBuf.length) {
            return false;
        }
        return timingSafeEqual(buf, storedBuf);
    }
}