const trim = (u) => (u ? u.replace(/\/+$/, '') : u);
const port = Number(process.env.PORT || 3000);

const baseUrl = trim(
  process.env.APP_BASE_URL ||
    (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${port}`)
);
const orgUrl = trim(process.env.OKTA_ORG_URL || '');

export const config = {
  port,
  baseUrl,
  orgUrl,
  // OIDC issuer. Use the org authorization server (= OKTA_ORG_URL) for this demo:
  // Okta signs the Universal Logout JWT with the org's SSO signing key and sets iss to
  // the org URL, so using the org AS keeps ID tokens and logout tokens on one issuer.
  issuer: trim(process.env.OKTA_ISSUER || orgUrl),
  clientId: process.env.OKTA_CLIENT_ID || '',
  clientSecret: process.env.OKTA_CLIENT_SECRET || '',
  redirectPath: '/authorization-code/callback',
  logoutPath: '/global-token-revocation', // register `${baseUrl}${logoutPath}` in Okta
  sessionSecret: process.env.SESSION_SECRET || 'dev-only-secret-change-me',
  // When false, a bad Universal Logout JWT is logged but the request is still processed.
  // Keep true for real use; set false only to debug a first integration.
  strictLogoutAuth: process.env.STRICT_LOGOUT_AUTH !== 'false',
};
