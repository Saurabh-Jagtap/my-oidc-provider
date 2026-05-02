import crypto from 'crypto'
import { exportJWK, jwtVerify, SignJWT, importPKCS8, importSPKI } from 'jose'
import { generateCodeChallenge } from '../utils/pkce.js'
import { oidcConfig } from '../config/oidc.config.js'
import { and, eq, lt, or } from 'drizzle-orm'
import { db } from '../db/index.js'
import { authorizationCodesTable, clientsTable, refreshTokensTable, userConsentsTable, usersTable } from '../db/schema.js'
import { PUBLIC_KEY, PRIVATE_KEY } from '../utils/cert.js'

let privateKey;
let publicKey;
let publicJWK;

privateKey = await importPKCS8(PRIVATE_KEY, "RS256");
publicKey = await importSPKI(PUBLIC_KEY, "RS256");

publicJWK = await exportJWK(publicKey);
publicJWK.kid = oidcConfig.keyId;
publicJWK.alg = "RS256";
publicJWK.use = 'sig';

const hashToken = (token) => {
    return crypto.createHash("sha256").update(token).digest("hex")
}

const createAccessToken = async ({ user, clientId, scope }) => {
    return new SignJWT({
        sub: user.id,
        scope,
        email: user.email,
        email_verified: user.emailVerified,
        given_name: user.firstName ?? "",
        family_name: user.lastName ?? "",
        name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    })
        .setProtectedHeader({ alg: "RS256", kid: oidcConfig.keyId })
        .setIssuer(oidcConfig.issuer)
        .setAudience(clientId)
        .setExpirationTime(oidcConfig.accessTokenExpiresIn)
        .sign(privateKey)
}

const createIdToken = async ({ user, clientId, nonce }) => {
    return new SignJWT({
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerified,
        given_name: user.firstName ?? "",
        family_name: user.lastName ?? "",
        name: [user.firstName, user.lastName].filter(Boolean).join(" "),
        nonce: nonce,
    })
        .setProtectedHeader({ alg: "RS256", kid: oidcConfig.keyId })
        .setIssuer(oidcConfig.issuer)
        .setAudience(clientId)
        .setIssuedAt()
        .setExpirationTime(oidcConfig.accessTokenExpiresIn)
        .sign(privateKey);
};

const createRefreshToken = async ({ userId, clientId, scope }) => {
    const refreshToken = crypto.randomBytes(64).toString("hex")

    await db.insert(refreshTokensTable).values({
        userId,
        clientId,
        scope,
        refreshTokenHash: hashToken(refreshToken),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    })

    return refreshToken
}

const normalizeScopes = (scopeStr = "") => {
    return scopeStr
        .split(" ")
        .map(s => s.trim().toLowerCase())
        .filter(Boolean);
};

const isSubset = (requested, stored) => {
    return requested.every(scope => stored.includes(scope));
};

const cleanupAuthorizationCodes = async () => {
    await db
        .delete(authorizationCodesTable)
        .where(
            or(
                lt(authorizationCodesTable.expiresAt, new Date()),
                eq(authorizationCodesTable.consumed, true)
            )
        );
};

export const getOpenIdConfiguration = (req, res) => {
    const baseURL = oidcConfig.issuer

    return res.json({
        issuer: baseURL,
        authorization_endpoint: `${baseURL}/auth`,
        token_endpoint: `${baseURL}/token`,
        userinfo_endpoint: `${baseURL}/userinfo`,
        jwks_uri: `${baseURL}/.well-known/jwks.json`,

        grant_types_supported: ["authorization_code", "refresh_token"],
        scopes_supported: ["openid", "profile", "email"],

        claims_supported: [
            "sub",
            "name",
            "email",
            "email_verified",
            "given_name",
            "family_name",
        ],
    })
}

export const getJwks = (req, res) => {
    res.json({
        keys: [publicJWK]
    })
}

export const authorize = async (req, res) => {
    const { redirect_uri, state, client_id, code_challenge, scope, nonce } = req.query;

    const allowedScopes = ["openid", "profile", "email"];
    const requestedScopes = normalizeScopes(scope);

    try {
        await cleanupAuthorizationCodes();
    } catch (err) {
        console.error("Cleanup failed:", {
            message: err.message,
            cause: err.cause,
            code: err.cause?.code,
            detail: err.cause?.detail,
            table: err.cause?.table,
            column: err.cause?.column,
        });

        // return res.status(500).json({
        //     error: "cleanup_failed",
        //     message: err.message,
        //     cause: err.cause?.message,
        //     code: err.cause?.code,
        // });
    }


    if (!client_id) {
        return res.status(400).json({ error: "missing_client_id" });
    }

    const [client] = await db
        .select()
        .from(clientsTable)
        .where(eq(clientsTable.clientId, client_id))
        .limit(1);

    if (!client) {
        return res.status(400).json({ error: "invalid_client" })
    }

    if (!nonce) {
        return res.status(400).json({ error: "missing_nonce" });
    }

    let redirectUris;
    try {
        redirectUris = JSON.parse(client.redirectUris);
    } catch {
        return res.status(500).json({ error: "invalid_client_redirect_uris" });
    }

    const normalize = (url) => new URL(url).toString();

    const isValidRedirect = redirectUris.some(
        (uri) => normalize(uri) === normalize(redirect_uri)
    );

    if (!isValidRedirect) {
        return res.status(400).json({ error: "invalid_redirect_uri" });
    }

    if (!requestedScopes.includes("openid")) {
        return res.status(400).json({ error: "invalid_scope" });
    }

    if (!requestedScopes.every(s => allowedScopes.includes(s))) {
        return res.status(400).json({ error: "unsupported_scope" });
    }

    if (!code_challenge) {
        return res.status(400).json({ error: "Missing code challenge" })
    }

    if (!state) {
        return res.status(400).json({ error: "Missing state" });
    }

    if (!req.session.authRequests) {
        req.session.authRequests = {};
    }

    if (!req.session.user) {
        req.session.authRequests[state] = {
            redirect_uri,
            state,
            client_id,
            code_challenge,
            scope,
            nonce
        }
        return res.redirect(`/login.html?state=${encodeURIComponent(state)}`)
    }

    const code = crypto.randomBytes(32).toString('hex');

    const [user] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, req.session.user.id))
        .limit(1)

    if (!user) {
        return res.status(400).json({ error: "login_required" })
    }

    const [consent] = await db
        .select()
        .from(userConsentsTable)
        .where(
            and(
                eq(userConsentsTable.userId, user.id),
                eq(userConsentsTable.clientId, client_id)
            )
        )
        .limit(1);

    let hasConsent = false;

    if (consent) {
        const storedScopes = normalizeScopes(consent.scopes);

        if (isSubset(requestedScopes, storedScopes)) {
            hasConsent = true;
        }
    }

    if (!hasConsent) {
        req.session.authRequests[state] = {
            redirect_uri,
            state,
            client_id,
            code_challenge,
            scope,
            nonce
        };

        return res.redirect(`/consent.html?state=${encodeURIComponent(state)}`);
    }

    await db.insert(authorizationCodesTable)
        .values({
            codeHash: hashToken(code),
            expiresAt: new Date(Date.now() + 60 * 1000),
            clientId: client_id,
            redirectUri: redirect_uri,
            codeChallenge: code_challenge,
            scope,
            nonce,
            userId: user.id,
        })

    delete req.session.authRequests[state];

    const redirectUrl = new URL(redirect_uri)
    redirectUrl.searchParams.set("code", code)
    redirectUrl.searchParams.set("state", state)
    return res.redirect(redirectUrl.toString())

}

export const token = async (req, res) => {
    try {
        const { code, client_id, redirect_uri, code_verifier, grant_type, refresh_token } = req.body;

        console.log("TOKEN REQUEST:", {
            grant_type,
            client_id
        });

        if (!grant_type) {
            return res.status(400).json({ error: "missing_grant_type" });
        }

        if (!["authorization_code", "refresh_token"].includes(grant_type)) {
            return res.status(400).json({ error: "unsupported_grant_type" });
        }

        if (!client_id) {
            return res.status(400).json({ error: "missing_client_id" });
        }

        const [client] = await db
            .select()
            .from(clientsTable)
            .where(eq(clientsTable.clientId, client_id))
            .limit(1);

        if (!client) {
            return res.status(400).json({ error: "invalid_client" });
        }

        // prevent revoked clients from using token endpoint
        if (client.revoked) {
            return res.status(400).json({ error: "invalid_client" });
        }

        if (client.clientSecret) {
            const { client_secret } = req.body;

            if (!client_secret) {
                return res.status(400).json({ error: "missing_client_secret" });
            }

            const hashed = crypto
                .createHash("sha256")
                .update(client_secret)
                .digest("hex");

            if (hashed !== client.clientSecret) {
                return res.status(400).json({ error: "invalid_client_secret" });
            }
        }

        if (grant_type === "authorization_code") {
            if (!code) {
                return res.status(400).json({ error: "missing_code" })
            }

            const codeHash = hashToken(code);
            const [stored] = await db
                .select()
                .from(authorizationCodesTable)
                .where(eq(authorizationCodesTable.codeHash, codeHash))
                .limit(1)


            if (!redirect_uri) {
                return res.status(400).json({ error: "missing_redirect_uri" })
            }

            if (!code_verifier) {
                return res.status(400).json({ error: 'missing_code_verifier' });
            }

            if (!stored) {
                return res.status(400).json({ error: "Invalid code" })
            }

            if (stored.consumed) {
                return res.status(400).json({ error: "code_already_used" });
            }

            if (Date.now() > stored.expiresAt.getTime()) {
                return res.status(400).json({ error: "code_expired" });
            }

            let redirectUris;
            try {
                redirectUris = JSON.parse(client.redirectUris);
            } catch {
                return res.status(400).json({ error: "invalid_client_redirect_uris" });
            }

            const normalize = (url) => new URL(url).toString();

            const isValidRedirect = redirectUris.some(
                (uri) => normalize(uri) === normalize(redirect_uri)
            );

            if (!isValidRedirect) {
                return res.status(400).json({ error: "invalid_redirect_uri" });
            }

            if (!isValidRedirect) {
                return res.status(400).json({ error: "invalid_redirect_uri" });
            }

            if (stored.clientId !== client_id || stored.redirectUri !== redirect_uri) {
                return res.status(400).json({ error: 'invalid_grant' });
            }

            if (!stored.codeChallenge) {
                return res.status(400).json({ error: 'pkce_required' });
            }

            const computedChallenge = generateCodeChallenge(code_verifier);

            if (computedChallenge !== stored.codeChallenge) {
                return res.status(400).json({ error: "Invalid code verifier" })
            }

            // IMP - one-time use
            const updatedCodes = await db
                .update(authorizationCodesTable)
                .set({ consumed: true })
                .where(
                    and(
                        eq(authorizationCodesTable.id, stored.id),
                        eq(authorizationCodesTable.consumed, false)
                    )
                )
                .returning();

            if (updatedCodes.length === 0) {
                return res.status(400).json({ error: "code_already_used" });
            }

            const [user] = await db
                .select()
                .from(usersTable)
                .where(eq(usersTable.id, stored.userId))
                .limit(1);

            if (!user) {
                return res.status(400).json({ error: "invalid_user" });
            }

            const accessToken = await createAccessToken({
                user,
                clientId: stored.clientId,
                scope: stored.scope,
            })

            const idToken = await createIdToken({
                user,
                clientId: stored.clientId,
                nonce: stored.nonce,
            });

            const newRefreshToken = await createRefreshToken({
                userId: user.id,
                clientId: stored.clientId,
                scope: stored.scope,
            })

            return res.json({
                access_token: accessToken,
                id_token: idToken,
                refresh_token: newRefreshToken,
                token_type: 'Bearer',
                expires_in: oidcConfig.accessTokenExpiresInSeconds,
            })

        }
        else if (grant_type === "refresh_token") {
            if (!refresh_token) {
                return res.status(400).json({ error: "missing_refresh_token" })
            }

            const refreshTokenHash = hashToken(refresh_token)

            const [storedRefresh] = await db
                .select()
                .from(refreshTokensTable)
                .where(
                    and(
                        eq(refreshTokensTable.refreshTokenHash, refreshTokenHash),
                        eq(refreshTokensTable.clientId, client_id)
                    )
                )
                .limit(1)

            if (!storedRefresh || storedRefresh.revoked) {
                return res.status(400).json({ error: "invalid_refresh_token" })
            }

            if (storedRefresh.expiresAt.getTime() < Date.now()) {
                await db.update(refreshTokensTable)
                    .set({ revoked: true })
                    .where(eq(refreshTokensTable.id, storedRefresh.id));
                return res.status(400).json({ error: "refresh_token_expired" })
            }

            const [user] = await db
                .select()
                .from(usersTable)
                .where(eq(usersTable.id, storedRefresh.userId))
                .limit(1)

            if (!user) {
                return res.status(400).json({ error: "invalid_user" })
            }

            const updated = await db
                .update(refreshTokensTable)
                .set({ revoked: true })
                .where(
                    and(
                        eq(refreshTokensTable.refreshTokenHash, refreshTokenHash),
                        eq(refreshTokensTable.clientId, client_id),
                        eq(refreshTokensTable.revoked, false),
                    )
                )
                .returning();

            if (updated.length === 0) {
                return res.status(400).json({ error: "invalid_refresh_token" })
            }

            const accessToken = await createAccessToken({
                user,
                clientId: storedRefresh.clientId,
                scope: storedRefresh.scope,
            })

            const newRefreshToken = await createRefreshToken({
                userId: user.id,
                clientId: storedRefresh.clientId,
                scope: storedRefresh.scope,
            })

            return res.json({
                access_token: accessToken,
                refresh_token: newRefreshToken,
                token_type: "Bearer",
                expires_in: oidcConfig.accessTokenExpiresInSeconds,
            })
        }
        else {
            return res.status(400).json({ error: "missing_grant_type" })
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "internal_server_error" });
    }
}

export const userinfo = async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: 'missing_token' })
    }

    const token = authHeader.split(' ')[1]

    try {
        const { payload } = await jwtVerify(token, publicKey, {
            issuer: oidcConfig.issuer,
        })

        const [user] = await db
            .select()
            .from(usersTable)
            .where(eq(usersTable.id, payload.sub))
            .limit(1);

        if (!user) {
            return res.status(401).json({ error: "invalid_token" });
        }

        const scopes = payload.scope?.split(" ") || [];
        const audience = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;

        const [client] = await db
            .select()
            .from(clientsTable)
            .where(eq(clientsTable.clientId, audience))
            .limit(1);

        if (!client) {
            return res.status(401).json({ error: "invalid_token" });
        }

        if (audience !== client.clientId) {
            return res.status(401).json({ error: "invalid_token" });
        }

        const response = { sub: payload.sub };

        if (scopes.includes("email")) {
            response.email = payload.email;
            response.email_verified = payload.email_verified;
        }

        if (scopes.includes("profile")) {
            response.name = payload.name;
            response.given_name = payload.given_name;
            response.family_name = payload.family_name;
        }

        return res.json(response);
    } catch (error) {
        return res.status(401).json({ error: 'invalid_token' });
    }
}

// OIDC Consent flow function
export const consent = async (req, res) => {
    const { state, action } = req.body;

    const request = req.session.authRequests?.[state];

    if (!request) {
        return res.status(400).json({ error: "invalid_state" });
    }

    if (action === "deny") {
        const redirectUrl = new URL(request.redirect_uri);
        redirectUrl.searchParams.set("error", "access_denied");

        delete req.session.authRequests[state];

        return res.redirect(redirectUrl.toString());
    }

    if (action !== "approve") {
        return res.status(400).json({ error: "invalid_consent_action" });
    }

    if (!req.session.user) {
        return res.status(401).json({ error: "login_required" });
    }

    const userId = req.session.user.id;
    const clientId = request.client_id;
    const scopes = request.scope;

    const requestedScopes = normalizeScopes(scopes);

    const [existing] = await db
        .select()
        .from(userConsentsTable)
        .where(
            and(
                eq(userConsentsTable.userId, userId),
                eq(userConsentsTable.clientId, clientId)
            )
        )
        .limit(1);

    let finalScopes = requestedScopes;

    if (existing) {
        const existingScopes = normalizeScopes(existing.scopes);

        finalScopes = Array.from(
            new Set([...existingScopes, ...requestedScopes])
        );
    }

    await db.insert(userConsentsTable)
        .values({
            userId,
            clientId,
            scopes: finalScopes.join(' '),
        })
        .onConflictDoUpdate({
            target: [userConsentsTable.userId, userConsentsTable.clientId],
            set: { scopes: finalScopes.join(' ') }
        });

    delete req.session.authRequests[state];

    const redirectUrl = new URL(`/auth`, oidcConfig.issuer);

    redirectUrl.searchParams.set("client_id", clientId);
    redirectUrl.searchParams.set("redirect_uri", request.redirect_uri);
    redirectUrl.searchParams.set("state", state);
    redirectUrl.searchParams.set("scope", request.scope);
    redirectUrl.searchParams.set("code_challenge", request.code_challenge);
    redirectUrl.searchParams.set("nonce", request.nonce);

    return res.redirect(redirectUrl.toString());
}

// Backend Consent flow function
export const getConsentData = async (req, res) => {
    const { state } = req.query;

    const request = req.session.authRequests?.[state];

    if (!request) {
        return res.status(400).json({ error: "invalid_state" });
    }

    const [client] = await db
        .select()
        .from(clientsTable)
        .where(eq(clientsTable.clientId, request.client_id))
        .limit(1);

    return res.json({
        clientName: client?.name || "Unknown App",
        scopes: normalizeScopes(request.scope),
    });

}
