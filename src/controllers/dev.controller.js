import crypto from 'crypto'
import { db } from '../db/index.js'
import { eq, and } from 'drizzle-orm'
import { usersTable } from '../db/schema.js'

export const registerDev = async (req, res) => {
    // 1. Extract email, password from req.body
    // 2. Validate input
    //    - email exists?
    //    - password length?
    // 3. Check if developer already exists
    //    - query developersTable where email = ?
    // 4. If exists:
    //    → return 409 (already registered)
    // 5. Hash password
    //    - salt + hash (reuse your current logic)
    // 6. Insert into developersTable
    // 7. Return success (201)

    const { email, password, firstName, lastName } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" })
    }

    const exists = await db
        .select({ id: usersTable.id })
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .limit(1);

    if (exists.length > 0) {
        return res.status(409).json({ error: "User already exists!" })
    }

    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.createHash("sha256").update(password + salt).digest('hex')

    await db.insert(usersTable)
        .values({
            firstName,
            lastName: lastName ?? null,
            email,
            password: hash,
            salt,
            role: "developer"
        })

    res.status(201).json({ message: "User registered successfully!" })
}

export const loginDev = async (req, res) => {
    // 1. Extract email, password
    // 2. Validate input
    // 3. Fetch developer from DB
    // 4. If not found:
    //    → return 401
    // 5. Hash incoming password with stored salt
    // 6. Compare with stored password
    // 7. If mismatch:
    //    → return 401
    // 8. Store in session:
    //    req.session.developer = {
    //      id,
    //      email
    //    }
    // 9. Return success
    const { email, password, state } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    const [developer] = await db
        .select()
        .from(usersTable)
        .where(
            and(
                eq(usersTable.email, email),
                eq(usersTable.role, "developer")
            ))
        .limit(1)

    if (!developer) {
        return res.status(401).json({ message: "Invalid email or password." });
    }

    const hash = crypto.createHash("sha256").update(password + developer.salt).digest("hex");

    if (hash !== developer.password) {
        return res.status(401).json({ message: "Invalid email or password." });
    }

    req.session.user = {
        id: developer.id,
        email: developer.email,
        role: developer.role
    }

    const authRequest = state ? req.session.authRequests?.[state] : null;

    if (authRequest) {
        const query = new URLSearchParams(authRequest).toString();
        delete req.session.authRequests[state];
        return res.json({ redirectTo: `/auth?${query}` });
    }

    return res.json({ redirectTo: "/dev-dashboard.html" });
}
