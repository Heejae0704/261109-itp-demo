// Build, sign and deliver Security Event Tokens (RFC 8417) to Okta.
import crypto from 'node:crypto';
import { SignJWT, decodeProtectedHeader, decodeJwt } from 'jose';
import { ALG } from './keys.js';

/**
 * Sign a SET.
 *
 * Header: { alg: RS256, typ: secevent+jwt, kid }
 * Claims: iss (must equal the issuer registered in Okta), aud (the Okta org URL),
 *         iat, jti (unique; Okta silently ignores a repeated jti), events.
 * No exp and no top-level sub: the subject lives inside each event.
 */
export async function signSet({ key, issuer, audience, events }) {
  return new SignJWT({ events })
    .setProtectedHeader({ alg: ALG, typ: 'secevent+jwt', kid: key.kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(key.privateKey);
}

/**
 * POST the SET to Okta's receiver endpoint.
 * Okta answers 202 Accepted (empty body) on success, or 400 with
 * {"err": "...", "description": "..."} where err is one of
 * authentication_failed | invalid_audience | invalid_issuer | invalid_key | invalid_request.
 * The endpoint needs no API token: the signature is the authentication.
 */
export async function pushSet({ endpoint, jwt }) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/secevent+jwt',
      Accept: 'application/json',
    },
    body: jwt,
  });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: res.status, ok: res.status === 202, body };
}

export function describeSet(jwt) {
  return { header: decodeProtectedHeader(jwt), payload: decodeJwt(jwt) };
}
