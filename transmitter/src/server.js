import express from 'express';
import { config, jwksUri } from './config.js';
import { loadSigningKey } from './keys.js';
import { EVENT_TYPES, RISK_LEVELS, INITIATING_ENTITIES, buildEvent } from './events.js';
import { signSet, pushSet, describeSet } from './set.js';
import { consolePage } from './ui.js';

const key = await loadSigningKey();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const history = []; // last deliveries, newest first, shown in the console

// ---------- Public SSF metadata (Okta reads these) ----------

// SSF transmitter configuration metadata (SSF 1.0 section 7.1).
// Okta's receiver reads `issuer` and `jwks_uri` from here when the provider is
// registered with settings.well_known_url. Must be served as application/json.
app.get('/.well-known/ssf-configuration', (_req, res) => {
  res.type('application/json').send({
    spec_version: '1_0',
    issuer: config.issuer,
    jwks_uri: jwksUri(),
    delivery_methods_supported: ['urn:ietf:rfc:8935'], // push delivery over HTTP
    authorization_schemes: [{ spec_urn: 'urn:ietf:rfc:7523' }],
    default_subjects: 'NONE',
  });
});

// Public signing keys. Okta requires an RS256 RSA key served as application/json.
app.get(config.jwksPath, (_req, res) => {
  res.type('application/json').send({ keys: [key.publicJwk] });
});

app.get('/healthz', (_req, res) => res.send('ok'));

// ---------- Admin console + API (password protected) ----------

function requireAdmin(req, res, next) {
  if (!config.adminPassword) return next(); // open when no password is configured (local dev)
  const [scheme, value] = (req.headers.authorization || '').split(' ');
  if (scheme === 'Basic' && value) {
    const pass = Buffer.from(value, 'base64').toString().split(':').slice(1).join(':');
    if (pass === config.adminPassword) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="SSF transmitter"').status(401).send('Authentication required');
}

app.get('/', requireAdmin, (_req, res) => {
  res.send(
    consolePage({
      config,
      jwksUri: jwksUri(),
      kid: key.kid,
      eventTypes: EVENT_TYPES,
      riskLevels: RISK_LEVELS,
      initiatingEntities: INITIATING_ENTITIES,
      history,
    })
  );
});

/**
 * Create, sign and (unless dryRun) push a SET.
 * Body: { type, email, reason?, initiatingEntity?, previousLevel?, currentLevel?, ..., dryRun? }
 */
app.post('/api/events', requireAdmin, async (req, res) => {
  const opts = { type: 'user-risk-change', ...(req.body || {}) };
  const dryRun = opts.dryRun === true || opts.dryRun === 'true' || opts.dryRun === 'on';
  try {
    if (!config.audience) throw new Error('OKTA_ORG_URL (or SET_AUDIENCE) is not configured');
    const events = buildEvent(opts.type, opts);
    const jwt = await signSet({ key, issuer: config.issuer, audience: config.audience, events });
    const decoded = describeSet(jwt);

    let delivery = { status: null, ok: null, body: 'dry run: not sent' };
    if (!dryRun) {
      if (!config.oktaSetEndpoint) throw new Error('OKTA_ORG_URL (or OKTA_SET_ENDPOINT) is not configured');
      delivery = await pushSet({ endpoint: config.oktaSetEndpoint, jwt });
    }

    const entry = { at: new Date().toISOString(), type: opts.type, email: opts.email, dryRun, delivery, decoded, jwt };
    history.unshift(entry);
    history.length = Math.min(history.length, 25);
    console.log(`[set] ${dryRun ? 'dry-run' : 'sent'} ${opts.type} for ${opts.email} -> ${delivery.status ?? '-'}`, delivery.body ?? '');

    res.status(dryRun || delivery.ok ? 200 : 502).json(entry);
  } catch (err) {
    console.error('[set] error', err);
    res.status(400).json({ error: err.message });
  }
});

app.listen(config.port, () => {
  console.log(`SSF transmitter listening on :${config.port}`);
  console.log(`  issuer           ${config.issuer}`);
  console.log(`  well-known       ${config.publicUrl}/.well-known/ssf-configuration`);
  console.log(`  jwks_uri         ${jwksUri()} (kid ${key.kid})`);
  console.log(`  SET audience     ${config.audience || '(not set: set OKTA_ORG_URL)'}`);
  console.log(`  SET endpoint     ${config.oktaSetEndpoint || '(not set: set OKTA_ORG_URL)'}`);
});
