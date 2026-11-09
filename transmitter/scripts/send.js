// CLI: trigger a SET through a running transmitter.
//   node scripts/send.js user@example.com [type] [--dry]
// Env: TRANSMITTER_URL (default http://localhost:4000), ADMIN_PASSWORD
const [email, type = 'user-risk-change', flag] = process.argv.slice(2);
if (!email) {
  console.error('usage: node scripts/send.js <email> [user-risk-change|session-revoked|...] [--dry]');
  process.exit(1);
}
const base = process.env.TRANSMITTER_URL || 'http://localhost:4000';
const headers = { 'Content-Type': 'application/json' };
if (process.env.ADMIN_PASSWORD) {
  headers.Authorization = 'Basic ' + Buffer.from(`admin:${process.env.ADMIN_PASSWORD}`).toString('base64');
}
const res = await fetch(`${base}/api/events`, {
  method: 'POST',
  headers,
  body: JSON.stringify({
    type,
    email,
    currentLevel: 'high',
    previousLevel: 'low',
    reason: 'Threat detected by custom SSF transmitter (CLI)',
    dryRun: flag === '--dry',
  }),
});
const json = await res.json();
console.log(JSON.stringify({ http: res.status, delivery: json.delivery, error: json.error, set: json.decoded }, null, 2));
