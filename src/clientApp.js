import express from "express";
import crypto from "crypto";

const app = express();
const PORT = 4000;

let pkceStore = {}; // temporary in-memory store

app.listen(PORT, () => {
  console.log(`Client app running on http://localhost:${PORT}`);
});

app.get("/", (req, res) => {
  res.send(`
    <h2>Client App</h2>
    <a href="/login">Login with OIDC</a>
  `);
});

function generateVerifier() {
  return crypto.randomBytes(32).toString("hex");
}

function generateChallenge(verifier) {
  return crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
}

app.get("/login", (req, res) => {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();

  const verifier = generateVerifier();
  const challenge = generateChallenge(verifier);

  // store PKCE temporarily
  pkceStore[state] = { verifier };

  const authUrl = new URL("http://localhost:3000/auth");

  authUrl.searchParams.set("client_id", "test-client");
  authUrl.searchParams.set("redirect_uri", "http://localhost:4000/callback");
  authUrl.searchParams.set("scope", "openid email profile");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("nonce", nonce);

  res.redirect(authUrl.toString());
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.send("Missing code/state");
  }

  const stored = pkceStore[state];

  if (!stored) {
    return res.send("Invalid state");
  }

  const verifier = stored.verifier;

  try {
    // exchange code for tokens
    const tokenRes = await fetch("http://localhost:3000/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: "test-client",
        redirect_uri: "http://localhost:4000/callback",
        code_verifier: verifier,
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) {
      return res.send("Token exchange failed: " + JSON.stringify(tokenData));
    }

    // call userinfo
    const userRes = await fetch("http://localhost:3000/userinfo", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const userData = await userRes.json();

    return res.send(`
      <h2>Login Success</h2>
      <pre>${JSON.stringify(userData, null, 2)}</pre>
    `);
  } catch (err) {
    console.error(err);
    res.send("Error during callback");
  }
});