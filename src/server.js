import express from 'express'
import dotenv from 'dotenv/config'
import { generateKeyPairSync } from 'crypto'
import { exportJWK, jwtVerify, SignJWT } from 'jose'
import crypto from 'crypto'
import session from 'express-session'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'
import { db } from './db/index.js'
import { usersTable } from './db/schema.js'
import { eq } from 'drizzle-orm'

const app = express();
const port = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// src/server.js
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:4000',
  'http://127.0.0.1:3001',
  'http://192.168.0.197:3001',
  ...(process.env.CORS_ORIGINS?.split(',').map(origin => origin.trim()).filter(Boolean) ?? [])
]


app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true)
        }

        return callback(new Error(`Origin ${origin} is not allowed by CORS`))
    },
    credentials: true
}))

app.use(express.json())
// app.use(express.static(path.join(__dirname, 'public')))

app.use(session({
    secret: 'super-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false // true in production (HTTPS)
    }
}));

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

let privateKey, publicKey, publicJWK;
const authCodes = new Map();
const clients = {
    "client_id_1": {
        redirect_uris: ["http://localhost:4000/callback"]
    }
}

async function initKeys() {
    const { publicKey: pubKey, privateKey: privKey } = await generateKeyPairSync('rsa', {
        modulusLength: 2048,
    })

    privateKey = privKey;
    publicKey = pubKey;
    publicJWK = await exportJWK(publicKey)
    publicJWK.kid = 'my-key-id'
    publicJWK.use = 'sig'
}

await initKeys()

function generateCodeChallenge(verifier) {
    return crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64url');
}

app.listen(port, () => {
    console.log(`Server listening on port: ${port}`)
})

app.get("/health", (req, res) =>
    res.json({ message: "Server is healthy", healthy: true }),
);

app.get('/debug-file', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/.well-known/openid-configuration', (req, res) => {
    const baseURL = 'http://localhost:3000';
    return res.json({
        issuer: baseURL,
        authorization_endpoint: `${baseURL}/auth`,
        token_endpoint: `${baseURL}/token`,
        userinfo_endpoint: `${baseURL}/userinfo`,
        jwks_uri: `${baseURL}/.well-known/jwks.json`
    })
})

app.get('/.well-known/jwks.json', (req, res) => {
    res.json({
        keys: [publicJWK]
    })
})

app.get('/auth', (req, res) => {
    const { redirect_uri, state, client_id, code_challenge } = req.query;

    const client = clients[client_id]

    if (!client || !client.redirect_uris.includes(redirect_uri)) {
        return res.status(400).json({ error: "Invalid redirect uri" })
    }

    if(!code_challenge){
        return res.status(400).json({error: "Missing code challenge"})
    }

    if(!req.session.user){
        req.session.authRequest = {
            redirect_uri,
            state,
            client_id,
            code_challenge
        }
        return res.redirect('/login.html')
    }

    const code = crypto.randomBytes(32).toString('hex');

    authCodes.set(code, {
        expiresAt: Date.now() + 60 * 1000,
        client_id,
        redirect_uri,
        code_challenge,
        user: req.session.user
    })

    return res.redirect(`${redirect_uri}?code=${code}&state=${state}`)
})

app.post('/token', async (req, res) => {
    const { code, client_id, redirect_uri, code_verifier } = req.body;
    const stored = authCodes.get(code);

    if (!code_verifier) {
        return res.status(400).json({ error: 'missing_code_verifier' });
    }

    if (!stored) {
        return res.status(400).json({ error: "Invalid code" })
    }

    if (stored.client_id !== client_id || stored.redirect_uri !== redirect_uri) {
        return res.status(400).json({ error: 'invalid_request' });
    }

    if (Date.now() > stored.expiresAt) {
        authCodes.delete(code);
        return res.status(400).json({ error: "Code expired" })
    }

    if (!stored.code_challenge) {
        return res.status(400).json({ error: 'pkce_required' });
    }

    const computedChallenge = generateCodeChallenge(code_verifier);

    if (computedChallenge !== stored.code_challenge) {
        return res.status(400).json({ error: "Invalid code verifier" })
    }

    // IMP - one-time use
    authCodes.delete(code);

    const ISSUER = `http://localhost:${port}`
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
        iss: ISSUER,
        sub: stored.user.id,
        email: stored.user.email,
        email_verified: String(stored.user.emailVerified),
        exp: now + 3600,
        given_name: stored.user.firstName ?? "",
        family_name: stored.user.lastName ?? "",
        name: [stored.user.firstName, stored.user.lastName].filter(Boolean).join(" "),
    })
        .setProtectedHeader({ alg: 'RS256', kid: 'my-key-id' })
        .setIssuer('http://localhost:3000')
        .setAudience('client_id')
        .setExpirationTime('1h')
        .sign(privateKey)

    return res.json({
        access_token: token,
        token_type: 'Bearer'
    })
})

app.get('/userinfo', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: 'missing_token' })
    }

    const token = authHeader.split(' ')[1]

    try {
        const { payload } = await jwtVerify(token, publicKey, {
            issuer: 'http://localhost:3000',
            audience: 'client_id_1'
        })

        return res.json({
            sub: payload.sub,
            name: payload.name,
            email: payload.email,
            email_verified: payload.email_verified,
            given_name: payload.given_name,
            family_name: payload.family_name
        })
    } catch (error) {
        return res.status(401).json({ error: 'invalid_token' });
    }

})

app.post('/o/auth/register', async (req, res) => {
    const { email, password, firstName, lastName } = req.body;

    if (!email || !password || !firstName) return res.status(400).json({ error: "All fields are required!" });
    
    const [existing] = await db
    .select({id: usersTable.id})
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
})

app.post('/o/auth/login', async (req, res) => {
    const { email, password } = req.body;

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
    const authRequest = req.session.authRequest;

    if (authRequest) {
        const query = new URLSearchParams(authRequest).toString();
        delete req.session.authRequest;
        return res.json({redirectTo: `/auth?${query}`});
    }

    return res.json({redirectTo: 'http://localhost:4000/dashboard.html'});
})
