/**
 * WSTG-IDNT-01: Test Role Definitions
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions.md
 *
 * WSTG-IDNT-03: Test Account Provisioning Process
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process.md
 *
 * WSTG-ATHZ-03: Testing for Privilege Escalation
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation.md
 *
 * WSTG-ATHZ-04: Testing for Insecure Direct Object References
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md
 *
 * WSTG-INPV-20: Testing for Mass Assignment
 * Reference: https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment.md
 *
 * Security enhancements:
 * - Schema-level validation for username and password fields
 * - Password field excluded from JSON serialization
 * - No admin/role field exposed to prevent privilege escalation
 * - Timestamps for audit trail
 */

import mongoose from "mongoose";
import { Password } from "../services/password"

interface UserAttrs {
    username: string;
    password: string;
};

interface UserModel extends mongoose.Model<UserDoc> {
    build(attrs: UserAttrs): UserDoc;
};

interface UserDoc extends mongoose.Document {
    username: string;
    password: string;
}

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        // WSTG-IDNT-05: Enforce username constraints at schema level
        minlength: 3,
        maxlength: 30,
        trim: true,
        // WSTG-INPV-05.6: Prevent NoSQL injection via schema validation
        validate: {
            validator: function (v: string) {
                return /^[a-zA-Z][a-zA-Z0-9_-]*$/.test(v);
            },
            message: 'Username must start with a letter and contain only letters, numbers, underscores, or hyphens'
        }
    },
    password: {
        type: String,
        required: true,
        // WSTG-ATHN-07: Minimum password length at schema level
        minlength: 8
    }
}, {
    // WSTG-IDNT-03: Timestamps for account provisioning audit trail
    timestamps: true
});

// WSTG-ATHZ-04 / WSTG-INPV-20: Control what fields are exposed in API responses
// Never expose password, internal MongoDB fields, or any potential role/admin fields
userSchema.set('toJSON', {
    transform(doc: any, ret: any) {
        ret.id = ret._id;
        delete ret._id;
        delete ret.password;  // WSTG-CRYP-03: Never expose password hashes
        delete ret.__v;
        delete ret.createdAt; // Don't expose internal timestamps to clients
        delete ret.updatedAt;
    }
})

userSchema.pre('save', async function (done) {
    if (this.isModified('password')) {
        const hashed = await Password.toHash(this.get('password'));
        this.set('password', hashed);
    }
    done();
});

// WSTG-IDNT-04: Create unique index on username to prevent duplicate accounts
// This also helps with account enumeration prevention at the DB level
userSchema.index({ username: 1 }, { unique: true });

const User = mongoose.models.User || mongoose.model<UserDoc, UserModel>('User', userSchema);

export { User };