import crypto from 'crypto'
import { eq } from 'drizzle-orm'
import { db } from '../db/index.js'
import { usersTable } from '../db/schema.js'

export const registerUser = async (req, res) => {
    const { email, password, firstName, lastName, role } = req.body;
    const { state } = req.query;

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

    const [newUser] = await db.insert(usersTable).values({
        firstName,
        lastName: lastName ?? null,
        email,
        password: hash,
        salt,
        role: role === "developer" ? "developer" : "user"
    }).returning();

    req.session.user = { id: newUser.id, email: newUser.email, role: newUser.role };

    // Check if we need to resume an OIDC flow
    const authRequest = state ? req.session.authRequests?.[state] : null;

    if (authRequest) {
        const query = new URLSearchParams(authRequest).toString();
        delete req.session.authRequests[state];
        // Redirect back to OIDC /auth to finish the handshake
        return res.status(201).json({ 
            message: "Registered!", 
            redirectTo: `/auth?${query}` 
        });
    }

    res.status(201).json({ message: "User registered successfully!" })
}

export const loginUser = async (req, res) => {
    const { email, password } = req.body;
    const {state} = req.query;

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

    req.session.user = {
        id: user.id,
        email: user.email,
        role: user.role
    };
    const authRequest = state ? req.session.authRequests?.[state] : null;

    if (authRequest) {
        const query = new URLSearchParams(authRequest).toString();
        delete req.session.authRequests[state];
        return res.json({ redirectTo: `/auth?${query}` });
    }

    if (user.role === "developer") {
        return res.json({ redirectTo: "/dev-dashboard.html" });
    }

    return res.json({ redirectTo: "/home.html" });
}

export const becomeDeveloper = async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    const userId = req.session.user.id;

    const [user] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, userId))
        .limit(1);

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    if (user.role === "developer") {
        return res.status(400).json({ error: "Already a developer" });
    }

    // Promote user
    await db
        .update(usersTable)
        .set({ role: "developer" })
        .where(eq(usersTable.id, userId));

    // Update session immediately
    req.session.user.role = "developer";

    return res.json({ message: "Promoted to developer successfully" });
};

export const logoutUser = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: "Could not log out" });
        }
        res.clearCookie('connect.sid'); // default express-session cookie name
        return res.json({ message: "Logged out successfully" });
    });
};