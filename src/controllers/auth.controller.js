import crypto from 'crypto'
import { eq } from 'drizzle-orm'
import { db } from '../db/index.js'
import { usersTable } from '../db/schema.js'

export const registerUser =  async (req, res) => {
    const { email, password, firstName, lastName } = req.body;

    if (!email || !password || !firstName) return res.status(400).json({ error: "All fields are required!" });

    const [existing] = await db
        .select({ id: usersTable.id })
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .limit(1)

    if (existing) {
        res
            .status(409)
            .json({ message: "An account with this email already exists." });
        return;
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.createHash("sha256").update(password + salt).digest('hex')

    await db.insert(usersTable).values({
        firstName,
        lastName: lastName ?? null,
        email,
        password: hash,
        salt
    })

    res.status(201).json({ message: "User registered successfully!" })
}

export const loginUser =  async (req, res) => {
    const { email, password, state } = req.body;

    const [user] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .limit(1)

    if (!user || !user.password) {
        res.status(401).json({ message: "Invalid email or password." });
        return;
    }

    const hash = crypto.createHash("sha256").update(password + user.salt).digest('hex')

    if (hash !== user.password) {
        res.status(401).json({ message: "Invalid email or password." });
        return;
    }

    req.session.user = user;
    const authRequest = state ? req.session.authRequests?.[state] : null;

    if (authRequest) {
        const query = new URLSearchParams(authRequest).toString();
        delete req.session.authRequests[state];
        return res.json({ redirectTo: `/auth?${query}` });
    }

    return res.json({ redirectTo: 'http://localhost:4000/dashboard.html' });
}
