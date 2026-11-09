// Minimal OIDC authorization-code + PKCE client and the Universal Logout token validator.
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, decodeJwt, decodeProtectedHeader } from 'jose';
import { config } from './config.js';

let discovery;
export async function getDiscovery() {
  if (!discovery) {
    const res = await fetch(`${config.issuer}/.well-known/openid-configuration`);
    if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
    discovery = await res.json();
  }
  return discovery;
}

const jwksCache = new Map();
function jwks(url) {
  if (!jwksCache.has(url)) jwksCache.set(url, createRemoteJWKSet(new URL(url)));
  return jwksCache.get(url);
}

export const redirectUri = () => `${config.baseUrl}${config.redirectPath}`;

export function newAuthState() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return {
    state: crypto.randomBytes(16).toString('base64url'),
    nonce: crypto.randomBytes(16).toString('base64url'),
    verifier,
    challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
  };
}

export async function authorizeUrl(s) {
  const d = await getDiscovery();
  const u = new URL(d.authorization_endpoint);
  u.search = new URLSearchParams({
    client_id: config.clientId,
    response_type: 'code',
    scope: 'openid profile email offline_access',
    redirect_uri: redirectUri(),
    state: s.state,
    nonce: s.nonce,
    code_challenge: s.challenge,
    code_challenge_method: 'S256',
  }).toString();
  return u.toString();
}

export async function exchangeCode(code, s) {
  const d = await getDiscovery();
  const res = await fetch(d.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
      Authorization: 'Basic ' + Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString('base64'),
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri(), code_verifier: s.verifier }),
  });
  const tokens = await res.json();
  if (!res.ok) throw new Error(`Token exchange failed: ${JSON.stringify(tokens)}`);

  const { payload } = await jwtVerify(tokens.id_token, jwks(d.jwks_uri), {
    issuer: d.issuer,
    audience: config.clientId,
  });
  if (payload.nonce !== s.nonce) throw new Error('nonce mismatch');
  return { tokens, claims: payload };
}

export async function endSessionUrl(idToken) {
  const d = await getDiscovery();
  const u = new URL(d.end_session_endpoint);
  u.search = new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: `${config.baseUrl}/` }).toString();
  return u.toString();
}

/**
 * Validate the bearer JWT Okta sends with a Universal Logout request.
 *
 * Per Okta's Universal Logout spec the token looks like private_key_jwt:
 *   header  typ = global-token-revocation+jwt, signed with the org's SSO signing key
 *   iss     the org URL (or custom domain), same issuer as the app's ID tokens
 *   sub     this app's client_id
 *   aud     the logout endpoint URL (no query or fragment)
 *   exp/nbf/iat  +-5 minutes, jti unique
 */
export async function verifyLogoutToken(authorization) {
  const [scheme, token] = (authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) throw new Error('missing Bearer token');

  const expected = {
    typ: 'global-token-revocation+jwt',
    issuer: [...new Set([config.orgUrl, config.issuer, `${config.orgUrl}/`, `${config.issuer}/`])],
    audience: `${config.baseUrl}${config.logoutPath}`,
    subject: config.clientId,
    clockTolerance: 60,
    requiredClaims: ['exp', 'iat', 'jti'],
  };

  // Org signing keys first, then the configured issuer's keys (covers custom authorization servers).
  const d = await getDiscovery().catch(() => null);
  const keyUrls = [...new Set([`${config.orgUrl}/oauth2/v1/keys`, d?.jwks_uri].filter(Boolean))];

  let lastErr;
  for (const url of keyUrls) {
    try {
      const { payload, protectedHeader } = await jwtVerify(token, jwks(url), expected);
      return { payload, protectedHeader, keysFrom: url };
    } catch (err) {
      lastErr = err;
      if (err.code !== 'ERR_JWKS_NO_MATCHING_KEY' && err.code !== 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') break;
    }
  }
  const e = new Error(`invalid logout token: ${lastErr?.code || ''} ${lastErr?.message}`);
  e.decoded = safeDecode(token);
  throw e;
}

function safeDecode(token) {
  try {
    return { header: decodeProtectedHeader(token), payload: decodeJwt(token) };
  } catch {
    return null;
  }
}
