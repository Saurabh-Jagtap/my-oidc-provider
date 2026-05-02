import express from "express";
import crypto from "crypto";
import session from "express-session";
import { jwtVerify, importSPKI } from "jose";
import { readFileSync } from "node:fs";
import path from "node:path";
import { configDotenv } from "dotenv";

const app = express();
const PORT = 4000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Client Session Management
app.use(session({
  secret: "client-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

// Store PKCE + nonce per state (In-memory for demo)
const store = {};

// Load PUBLIC KEY for OIDC validation
const PUBLIC_KEY = readFileSync(path.resolve("cert/public-key.pub"), "utf8");
const publicKey = await importSPKI(PUBLIC_KEY, "RS256");

// CONFIGURATION
const OIDC_PROVIDER_URL = "http://localhost:3000";
const MY_CLIENT_ID = process.env.MY_CLIENT_ID; 
const MY_CLIENT_SECRET = process.env.MY_CLIENT_SECRET;
const REDIRECT_URI = "http://localhost:4000/callback";

// PKCE helpers
function generateVerifier() {
  return crypto.randomBytes(32).toString("hex");
}

function generateChallenge(verifier) {
  return crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
}

// Home
app.get("/", (req, res) => {
  const user = req.session.user;

  if (user) {
    return res.send(`
      <div style="font-family: sans-serif; padding: 40px; text-align: center; background: #f8fafc; min-height: 100vh;">
        <h2 style="color: #1e293b;">Welcome, ${user.name || user.email}!</h2>
        <p style="color: #64748b;">You are logged in to the Client Demo App.</p>
        
        <div style="margin: 20px 0; background: #fff; border: 1px solid #e2e8f0; padding: 20px; border-radius: 12px; display: inline-block; text-align: left;">
            <strong>Profile Details:</strong>
            <pre style="font-size: 13px; color: #475467;">${JSON.stringify(user, null, 2)}</pre>
        </div>

        <br>
        <a href="/logout" style="display: inline-block; background: #ef4444; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 10px;">
          Logout from Client
        </a>
      </div>
    `);
  }

  res.send(`
    <div style="font-family: sans-serif; padding: 40px; text-align: center; background: #f8fafc; min-height: 100vh;">
      <h2 style="color: #1e293b;">OIDC Client Demo</h2>
      <p style="color: #64748b;">Experience the full OpenID Connect flow</p>
      <a href="/login" style="display: inline-block; background: #00a676; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 20px;">
        Login with OIDC
      </a>
    </div>
  `);
});

// LOGIN START
app.get("/login", (req, res) => {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();

  const verifier = generateVerifier();
  const challenge = generateChallenge(verifier);

  // Store for callback validation
  store[state] = {
    verifier,
    nonce,
  };

  const authUrl = new URL(`${OIDC_PROVIDER_URL}/auth`);
  authUrl.searchParams.set("client_id", MY_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid email profile");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("nonce", nonce);

  res.redirect(authUrl.toString());
});

// CALLBACK
app.get("/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`Auth Error: ${error}`);
  }

  if (!code || !state) {
    return res.status(400).send("Missing code or state from provider");
  }

  const stored = store[state];
  if (!stored) {
    return res.status(400).send("Invalid state: Request might be forged or expired.");
  }

  const { verifier, nonce } = stored;
  delete store[state]; // Clean up

  try {
    // 1. Exchange authorization code for tokens
    const tokenRes = await fetch(`${OIDC_PROVIDER_URL}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: MY_CLIENT_ID,
        client_secret: MY_CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenRes.ok) {
      return res.status(tokenRes.status).send(`Token exchange failed: ${JSON.stringify(tokenData)}`);
    }

    // 2. Verify ID Token
    const { payload } = await jwtVerify(tokenData.id_token, publicKey, {
      issuer: OIDC_PROVIDER_URL,
      audience: MY_CLIENT_ID,
    });

    // 3. Nonce Check
    if (payload.nonce !== nonce) {
      return res.status(403).send("Security Error: Nonce mismatch.");
    }

    // 4. Fetch UserInfo (Using Access Token)
    const userRes = await fetch(`${OIDC_PROVIDER_URL}/userinfo`, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const userData = await userRes.json();

    // 5. Establish Client Session
    req.session.user = {
        ...payload,
        ...userData,
        accessToken: tokenData.access_token // for debug
    };

    res.redirect("/");
  } catch (err) {
    console.error("Callback Error:", err);
    res.status(500).send("Internal Error during token exchange or verification.");
  }
});

// LOGOUT
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.listen(PORT, () => {
  console.log(`\x1b[32m[Client App]\x1b[0m Ready at http://localhost:${PORT}`);
});
