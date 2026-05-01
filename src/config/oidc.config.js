export const oidcConfig = {
  issuer: process.env.OIDC_ISSUER || 'http://localhost:3000',
  keyId: process.env.OIDC_KEY_ID || 'my-key-id',
  accessTokenExpiresIn: '1h',
  accessTokenExpiresInSeconds: 3600,
}
