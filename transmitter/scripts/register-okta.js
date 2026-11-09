// Register this transmitter in Okta as a Security Events Provider via the SSF Receiver API.
//
//   OKTA_ORG_URL=https://your-org.okta.com OKTA_API_TOKEN=00x... \
//   TRANSMITTER_URL=https://your-transmitter.up.railway.app \
//   node scripts/register-okta.js [--jwks]          # create (well-known URL by default)
//   node scripts/register-okta.js --list            # list providers
//
// API: POST /api/v1/security-events-providers
//   { name, type, settings: { well_known_url } }           SSF-compliant provider
//   { name, type, settings: { issuer, jwks_url } }         non-SSF provider
// Auth: an admin API token (Authorization: SSWS <token>).
//
// `type` is a free-form "application type" string (Okta's schema doesn't enumerate it).
// The Admin Console path (Security > Device Integrations > Receive shared signals >
// Create stream) needs no type at all and is the simplest way for a demo.
const org = (process.env.OKTA_ORG_URL || '').replace(/\/+$/, '');
const token = process.env.OKTA_API_TOKEN;
const transmitter = (process.env.TRANSMITTER_URL || '').replace(/\/+$/, '');
const args = process.argv.slice(2);

if (!org || !token) {
  console.error('Set OKTA_ORG_URL and OKTA_API_TOKEN');
  process.exit(1);
}

const headers = { Authorization: `SSWS ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' };
const api = `${org}/api/v1/security-events-providers`;

if (args.includes('--list')) {
  const res = await fetch(api, { headers });
  console.log(res.status, JSON.stringify(await res.json(), null, 2));
  process.exit(0);
}

if (!transmitter) {
  console.error('Set TRANSMITTER_URL (public base URL of the deployed transmitter)');
  process.exit(1);
}

// Read issuer/jwks_uri from our own metadata so what we register matches what we sign with.
const meta = await (await fetch(`${transmitter}/.well-known/ssf-configuration`)).json();

const body = {
  name: process.env.OKTA_PROVIDER_NAME || 'Custom SSF Transmitter (demo)',
  type: process.env.OKTA_PROVIDER_TYPE || 'custom',
  settings: args.includes('--jwks')
    ? { issuer: meta.issuer, jwks_url: meta.jwks_uri }
    : { well_known_url: `${transmitter}/.well-known/ssf-configuration` },
};

console.log('POST', api, JSON.stringify(body, null, 2));
const res = await fetch(api, { method: 'POST', headers, body: JSON.stringify(body) });
console.log(res.status, JSON.stringify(await res.json(), null, 2));
