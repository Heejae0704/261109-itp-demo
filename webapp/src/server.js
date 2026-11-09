import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config.js';
import { authorizeUrl, newAuthState, exchangeCode, endSessionUrl, verifyLogoutToken } from './oidc.js';
import { createSession, getSession, deleteSession, listSessions, revokeUser, isKnownUser } from './sessions.js';
import { page } from './ui.js';

const app = express();
app.set('trust proxy', 1); // Railway terminates TLS in front of us
app.use(cookieParser(config.sessionSecret));

const secure = config.baseUrl.startsWith('https://');
const cookieOpts = { httpOnly: true, sameSite: 'lax', secure, signed: true };
const logoutLog = []; // Universal Logout requests received, newest first

const current = (req) => getSession(req.signedCookies.sid);

// ---------- Pages ----------

app.get('/', (req, res) => {
  const s = current(req);
  res.send(page({ config, session: s, sessions: listSessions(), logoutLog, kicked: req.query.kicked === '1' }));
});

// Polled by the browser so the demo visibly reacts when Okta revokes the session.
app.get('/api/me', (req, res) => {
  const s = current(req);
  res.json({ authenticated: !!s, user: s?.user || null });
});

// ---------- OIDC login / logout ----------

app.get('/login', async (req, res, next) => {
  try {
    const s = newAuthState();
    res.cookie('auth', JSON.stringify(s), { ...cookieOpts, maxAge: 10 * 60 * 1000 });
    res.redirect(await authorizeUrl(s));
  } catch (e) {
    next(e);
  }
});

app.get(config.redirectPath, async (req, res, next) => {
  try {
    if (req.query.error) throw new Error(`${req.query.error}: ${req.query.error_description}`);
    const s = JSON.parse(req.signedCookies.auth || 'null');
    if (!s || s.state !== req.query.state) throw new Error('state mismatch: start again from /login');
    const { tokens, claims } = await exchangeCode(req.query.code, s);
    const sid = createSession(
      { sub: claims.sub, iss: claims.iss, email: claims.email || claims.preferred_username, name: claims.name },
      { id_token: tokens.id_token, refresh_token: tokens.refresh_token, access_token: tokens.access_token }
    );
    res.clearCookie('auth', cookieOpts);
    res.cookie('sid', sid, cookieOpts);
    res.redirect('/');
  } catch (e) {
    next(e);
  }
});

app.post('/logout', async (req, res) => {
  const s = current(req);
  res.clearCookie('sid', cookieOpts);
  if (!s) return res.redirect('/');
  deleteSession(s.sid);
  res.redirect(await endSessionUrl(s.tokens.id_token));
});

// ---------- Universal Logout (Global Token Revocation) ----------
//
// Okta calls this when an entity risk / session protection policy action logs the user
// out of apps. Request:
//   POST /global-token-revocation
//   Authorization: Bearer <JWT typ=global-token-revocation+jwt>
//   {"sub_id": {"format": "email", "email": "..."}}
//   or {"sub_id": {"format": "iss_sub", "iss": "...", "sub": "..."}}
// Responses Okta understands: 204 revoked, 400 bad request, 401 bad auth,
// 404 unknown user, 422 cannot log out. Okta ignores the response body.
app.post(config.logoutPath, express.json({ type: () => true }), async (req, res) => {
  const entry = { at: new Date().toISOString(), body: req.body, status: null, note: '' };
  logoutLog.unshift(entry);
  logoutLog.length = Math.min(logoutLog.length, 25);
  const reply = (status, note) => {
    entry.status = status;
    entry.note = note;
    console.log(`[universal-logout] ${status} ${note}`, JSON.stringify(req.body));
    res.status(status).end();
  };

  try {
    const { payload, keysFrom } = await verifyLogoutToken(req.headers.authorization);
    entry.token = { iss: payload.iss, sub: payload.sub, aud: payload.aud, jti: payload.jti, keysFrom };
  } catch (err) {
    entry.token = err.decoded?.payload;
    if (config.strictLogoutAuth) return reply(401, err.message);
    entry.note = `(auth not enforced) ${err.message}. `;
  }

  const subId = req.body?.sub_id;
  const valid =
    subId &&
    ((subId.format === 'email' && typeof subId.email === 'string') ||
      (subId.format === 'iss_sub' && typeof subId.iss === 'string' && typeof subId.sub === 'string'));
  if (!valid) return reply(400, `${entry.note}unsupported or malformed sub_id`);

  if (!isKnownUser(subId)) return reply(404, `${entry.note}user never signed in to this app`);
  const n = revokeUser(subId);
  return reply(204, `${entry.note}revoked ${n} session(s)`);
});

app.get('/healthz', (_req, res) => res.send('ok'));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).send(`<pre>${String(err.message).replace(/</g, '&lt;')}</pre><p><a href="/">Back</a></p>`);
});

app.listen(config.port, () => {
  console.log(`Web app listening on :${config.port}`);
  console.log(`  base URL               ${config.baseUrl}`);
  console.log(`  OIDC issuer            ${config.issuer || '(not set)'}`);
  console.log(`  sign-in redirect URI   ${config.baseUrl}${config.redirectPath}`);
  console.log(`  sign-out redirect URI  ${config.baseUrl}/`);
  console.log(`  Universal Logout URL   ${config.baseUrl}${config.logoutPath}`);
});
