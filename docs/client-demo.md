import express, { application } from 'express'
import crypto, { hash } from 'crypto'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import path from 'path';
import { fileURLToPath } from 'url';

const app = express()
const port = 4000

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cookieParser())
app.use(cors({
  origin: 'http://localhost:4000',
  credentials: true
}))
// app.use(express.static(path.join(__dirname, 'public')));

function generateCodeChallenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});


app.get("/", (req, res) => res.json({ message: "Hello from Auth Server" }));

app.get("/health", (req, res) =>
  res.json({ message: "Server is healthy", healthy: true }),
);

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(32).toString('hex')
  const code_verifier = crypto.randomBytes(32).toString('hex');
  const code_challenge = generateCodeChallenge(code_verifier);

  res.cookie('oauth_state', state, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false // True in prod
  });
  res.cookie('code_verifier', code_verifier, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false // True in prod
  });

  const baseURL = 'http://localhost:3000'
  res.redirect(`${baseURL}/auth?client_id=client_id_1&code_challenge=${code_challenge}&redirect_uri=http://localhost:4000/callback&state=${state}`)
})

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const storedState = req.cookies.oauth_state;
  const code_verifier = req.cookies.code_verifier;

  if (state !== storedState) {
    return res.status(400).json({ error: "Invalid state" })
  }

  try {
    const baseURL = 'http://localhost:3000'
    const response = await fetch(`${baseURL}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        code,
        client_id: 'client_id_1',
        redirect_uri: `http://localhost:4000/callback`,
        code_verifier
      })
    })

    const data = await response.json()
    console.log("Token response:", data);

    if (!response.ok) {
      return res.status(400).json(data);
    }


    res.clearCookie('oauth_state');
    res.clearCookie('code_verifier');

    res.redirect('/dashboard.html');

  } catch (error) {
    return res.status(400).send("Token exchange failed");
  }
});

app.listen(port, () => {
  console.log(`Client running on port: ${port}`)
})
