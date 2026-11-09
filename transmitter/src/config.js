// Runtime configuration. See .env.example for every variable.
function trimSlash(u) {
  return u ? u.replace(/\/+$/, '') : u;
}

const port = Number(process.env.PORT || 4000);

// Public base URL of this transmitter. On Railway, RAILWAY_PUBLIC_DOMAIN is injected
// automatically once you generate a domain for the service.
const publicUrl = trimSlash(
  process.env.PUBLIC_URL ||
    (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${port}`)
);

const oktaOrgUrl = trimSlash(process.env.OKTA_ORG_URL || '');

export const config = {
  port,
  publicUrl,
  // `iss` of every SET. It must match the issuer Okta stores for the provider
  // (the `issuer` in our ssf-configuration, or settings.issuer in the API call), exactly.
  issuer: trimSlash(process.env.SSF_ISSUER || publicUrl),
  jwksPath: '/.well-known/jwks.json',
  // Okta org URL, e.g. https://acme.okta.com (no trailing slash, no /oauth2/default).
  oktaOrgUrl,
  // `aud` of every SET: Okta requires the Okta org URL.
  audience: trimSlash(process.env.SET_AUDIENCE || oktaOrgUrl),
  // Where SETs are pushed.
  oktaSetEndpoint: process.env.OKTA_SET_ENDPOINT || (oktaOrgUrl ? `${oktaOrgUrl}/security/api/v1/security-events` : ''),
  // Protects the console and the /api/events endpoint (HTTP Basic, any username).
  adminPassword: process.env.ADMIN_PASSWORD || '',
  // Optional: send a Universal Logout-friendly default email in the console form.
  defaultEmail: process.env.DEFAULT_SUBJECT_EMAIL || '',
};

export function jwksUri() {
  return `${config.publicUrl}${config.jwksPath}`;
}
