// A stand-in for an Okta org, for local end-to-end testing only.
// It plays the three Okta roles in the demo:
//   1. OIDC provider for the web app (discovery, authorize, token, keys, logout)
//   2. SSF receiver: verifies SETs the way Okta documents it
//   3. Universal Logout sender: on an accepted high-risk SET, calls the app's logout endpoint
import crypto from 'node:crypto';
import express from 'express';
import { SignJWT, exportJWK, generateKeyPair, jwtVerify, createRemoteJWKSet, decodeProtectedHeader } from 'jose';

const PORT = Number(process.env.FAKE_OKTA_PORT || 5055);
const ORG = `http://localhost:${PORT}`;
const PROVIDER_WELL_KNOWN = process.env.PROVIDER_WELL_KNOWN; // transmitter ssf-configuration
const APP_LOGOUT_URL = process.env.APP_LOGOUT_URL;
const CLIENT_ID = 'demo-client';
const USER = { sub: '00u_demo_user', email: 'demo.user@example.com', name: 'Demo User' };

const ACCEPTED_EVENTS = new Set([
  'https://schemas.okta.com/secevent/okta/event-type/user-risk-change',
  'https://schemas.okta.com/secevent/okta/event-type/device-risk-change',
  'https://schemas.okta.com/secevent/okta/event-type/ip-change',
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
  'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
]);

const { privateKey, publicKey } = await generateKeyPair('RS256');
const pub = { ...(await exportJWK(publicKey)), kid: 'okta-org-key', use: 'sig', alg: 'RS256' };
const codes = new Map();
const seenJti = new Set();
export const received = [];

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get('/.well-known/openid-configuration', (_q, r) =>
  r.json({
    issuer: ORG,
    authorization_endpoint: `${ORG}/oauth2/v1/authorize`,
    token_endpoint: `${ORG}/oauth2/v1/token`,
    jwks_uri: `${ORG}/oauth2/v1/keys`,
    end_session_endpoint: `${ORG}/oauth2/v1/logout`,
  })
);
app.get('/oauth2/v1/keys', (_q, r) => r.json({ keys: [pub] }));
app.get('/oauth2/v1/authorize', (q, r) => {
  const code = crypto.randomUUID();
  codes.set(code, { nonce: q.query.nonce, challenge: q.query.code_challenge });
  const u = new URL(q.query.redirect_uri);
  u.searchParams.set('code', code);
  u.searchParams.set('state', q.query.state);
  r.redirect(u.toString());
});
app.post('/oauth2/v1/token', async (q, r) => {
  const c = codes.get(q.body.code);
  const pkceOk = c && crypto.createHash('sha256').update(q.body.code_verifier).digest('base64url') === c.challenge;
  if (!pkceOk) return r.status(400).json({ error: 'invalid_grant' });
  const id_token = await new SignJWT({ nonce: c.nonce, email: USER.email, name: USER.name })
    .setProtectedHeader({ alg: 'RS256', kid: pub.kid })
    .setIssuer(ORG).setAudience(CLIENT_ID).setSubject(USER.sub).setIssuedAt().setExpirationTime('1h')
    .sign(privateKey);
  r.json({ id_token, access_token: 'at', refresh_token: 'rt', token_type: 'Bearer' });
});

// --- SSF receiver: mirrors Okta's documented checks ---
app.post('/security/api/v1/security-events', express.text({ type: '*/*' }), async (q, r) => {
  const fail = (err, description) => {
    received.push({ ok: false, err, description });
    r.status(400).json({ err, description });
  };
  if (q.headers['content-type'] !== 'application/secevent+jwt') return fail('invalid_request', 'bad content-type');
  try {
    const meta = await (await fetch(PROVIDER_WELL_KNOWN)).json();
    const h = decodeProtectedHeader(q.body);
    if (h.typ !== 'secevent+jwt' || h.alg !== 'RS256' || !h.kid) return fail('invalid_request', `bad header ${JSON.stringify(h)}`);
    let payload;
    try {
      ({ payload } = await jwtVerify(q.body, createRemoteJWKSet(new URL(meta.jwks_uri)), { algorithms: ['RS256'] }));
    } catch (e) {
      return fail('invalid_key', e.message);
    }
    if (payload.iss !== meta.issuer) return fail('invalid_issuer', `${payload.iss} != ${meta.issuer}`);
    if (payload.aud !== ORG) return fail('invalid_audience', `${payload.aud} != ${ORG}`);
    if (!payload.jti || typeof payload.iat !== 'number') return fail('invalid_request', 'jti/iat missing');
    if (seenJti.has(payload.jti)) return r.status(202).end(); // Okta silently ignores duplicates
    seenJti.add(payload.jti);
    const [[type, ev]] = Object.entries(payload.events || {});
    if (!ACCEPTED_EVENTS.has(type)) return fail('invalid_request', `unsupported event ${type}`);
    if (ev.subject?.user?.format !== 'email' || !ev.subject.user.email) return fail('invalid_request', 'subject must be user/email');
    if (typeof ev.event_timestamp !== 'number') return fail('invalid_request', 'event_timestamp missing');
    received.push({ ok: true, type, ev });
    r.status(202).end();

    // Simulated entity risk policy: high risk or session revoked -> Universal Logout.
    if (ev.current_level === 'high' || type.endsWith('/session-revoked')) {
      const gtr = await new SignJWT({})
        .setProtectedHeader({ alg: 'RS256', kid: pub.kid, typ: 'global-token-revocation+jwt' })
        .setJti(crypto.randomUUID()).setIssuer(ORG).setSubject(CLIENT_ID).setAudience(APP_LOGOUT_URL)
        .setIssuedAt().setNotBefore('-5m').setExpirationTime('5m')
        .sign(privateKey);
      const res = await fetch(APP_LOGOUT_URL, {
        method: 'POST',
        headers: { Authorization: `Bearer ${gtr}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ sub_id: { format: 'email', email: ev.subject.user.email } }),
      });
      received.push({ universalLogout: res.status });
    }
  } catch (e) {
    fail('invalid_request', e.message);
  }
});
app.get('/_received', (_q, r) => r.json(received));

app.listen(PORT, () => console.log(`fake okta on ${ORG}`));
