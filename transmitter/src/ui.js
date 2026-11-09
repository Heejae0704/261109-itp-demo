const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function consolePage({ config, jwksUri, kid, eventTypes, riskLevels, initiatingEntities, history }) {
  const typeOptions = Object.entries(eventTypes)
    .map(([k, d]) => `<option value="${k}"${d.recommended ? ' selected' : ''}>${esc(d.label)}${d.recommended ? ' (recommended)' : ''}</option>`)
    .join('');
  const levelOptions = (sel) => riskLevels.map((l) => `<option${l === sel ? ' selected' : ''}>${l}</option>`).join('');
  const entityOptions = initiatingEntities.map((e) => `<option${e === 'policy' ? ' selected' : ''}>${e}</option>`).join('');

  const rows = history
    .map(
      (h) => `<tr>
        <td>${esc(h.at.replace('T', ' ').slice(0, 19))}</td>
        <td>${esc(h.type)}</td>
        <td>${esc(h.email)}</td>
        <td class="${h.dryRun ? '' : h.delivery.ok ? 'ok' : 'bad'}">${h.dryRun ? 'dry run' : esc(h.delivery.status)}</td>
        <td><code>${esc(h.dryRun ? '' : typeof h.delivery.body === 'string' ? h.delivery.body : JSON.stringify(h.delivery.body))}</code></td>
      </tr>`
    )
    .join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSF Transmitter</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --fg:#1c1f24; --muted:#5b6370; --line:#dde1e6; --accent:#3b5bdb; --ok:#2b8a3e; --bad:#c92a2a; }
  @media (prefers-color-scheme: dark) { :root { --bg:#14161a; --card:#1d2026; --fg:#e7e9ec; --muted:#9aa3ad; --line:#2e333b; --accent:#7d95ff; --ok:#69db7c; --bad:#ff8787; } }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); }
  main { max-width: 980px; margin: 0 auto; padding: 24px 16px 64px; }
  h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 0 0 12px; }
  .muted { color: var(--muted); }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px; margin-top:18px; }
  dl { display:grid; grid-template-columns: max-content 1fr; gap:6px 16px; margin:0; }
  dt { color:var(--muted); } dd { margin:0; word-break: break-all; }
  label { display:block; font-size:13px; color:var(--muted); margin-bottom:4px; }
  input, select, textarea { width:100%; padding:8px 10px; border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); font:inherit; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; }
  button { padding:9px 16px; border:0; border-radius:6px; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
  button.secondary { background:transparent; color:var(--accent); border:1px solid var(--accent); }
  .actions { display:flex; gap:10px; margin-top:14px; flex-wrap: wrap; align-items:center; }
  pre { background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:12px; overflow:auto; font-size:12.5px; }
  table { width:100%; border-collapse: collapse; font-size:13px; } td, th { text-align:left; padding:6px 8px; border-top:1px solid var(--line); vertical-align: top; }
  .ok { color:var(--ok); font-weight:600; } .bad { color:var(--bad); font-weight:600; }
  .hidden { display:none; } .wrap { overflow-x:auto; }
</style></head>
<body><main>
  <h1>SSF Transmitter</h1>
  <div class="muted">Signs Security Event Tokens and pushes them to Okta Identity Threat Protection.</div>

  <section class="card">
    <h2>Registration values for Okta</h2>
    <dl>
      <dt>Well-known URL</dt><dd><code>${esc(config.publicUrl)}/.well-known/ssf-configuration</code></dd>
      <dt>Issuer</dt><dd><code>${esc(config.issuer)}</code></dd>
      <dt>JWKS URL</dt><dd><code>${esc(jwksUri)}</code> (kid <code>${esc(kid)}</code>)</dd>
      <dt>SET audience</dt><dd><code>${esc(config.audience || 'not set: configure OKTA_ORG_URL')}</code></dd>
      <dt>Push endpoint</dt><dd><code>${esc(config.oktaSetEndpoint || 'not set: configure OKTA_ORG_URL')}</code></dd>
    </dl>
  </section>

  <section class="card">
    <h2>Simulate a threat detection</h2>
    <form id="f">
      <div class="grid">
        <div><label>Event type</label><select name="type" id="type">${typeOptions}</select></div>
        <div><label>User email (Okta sign-in email)</label><input name="email" type="email" required value="${esc(config.defaultEmail)}" placeholder="user@example.com"></div>
        <div><label>Initiating entity</label><select name="initiatingEntity">${entityOptions}</select></div>
      </div>
      <div class="grid" style="margin-top:12px">
        <div data-for="user-risk-change device-risk-change"><label>Previous level</label><select name="previousLevel">${levelOptions('low')}</select></div>
        <div data-for="user-risk-change device-risk-change"><label>Current level</label><select name="currentLevel">${levelOptions('high')}</select></div>
        <div data-for="device-compliance-change"><label>Previous status</label><select name="previousStatus"><option>compliant</option><option>not-compliant</option></select></div>
        <div data-for="device-compliance-change"><label>Current status</label><select name="currentStatus"><option>not-compliant</option><option>compliant</option></select></div>
        <div data-for="ip-change session-revoked"><label>Previous / last known IP</label><input name="previousIp" placeholder="203.0.113.10"></div>
        <div data-for="ip-change session-revoked"><label>Current IP</label><input name="currentIp" placeholder="198.51.100.77"></div>
        <div data-for="identifier-changed"><label>New identifier value</label><input name="newValue" placeholder="new.email@example.com"></div>
      </div>
      <div style="margin-top:12px"><label>Reason (shown to admins in Okta)</label>
        <input name="reason" value="Impossible travel and credential stuffing detected by custom XDR"></div>
      <div class="actions">
        <button type="submit">Sign and send to Okta</button>
        <button type="button" class="secondary" id="dry">Preview only (sign, don't send)</button>
        <span id="status" class="muted"></span>
      </div>
    </form>
    <div id="out" class="hidden">
      <h2 style="margin-top:18px">Okta response</h2><pre id="resp"></pre>
      <h2>Decoded SET</h2><pre id="decoded"></pre>
      <h2>Compact JWT</h2><pre id="jwt" style="white-space:pre-wrap;word-break:break-all"></pre>
    </div>
  </section>

  <section class="card">
    <h2>Recent deliveries</h2>
    <div class="wrap"><table><thead><tr><th>Time (UTC)</th><th>Type</th><th>Subject</th><th>HTTP</th><th>Okta body</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5" class="muted">Nothing sent yet.</td></tr>'}</tbody></table></div>
  </section>
</main>
<script>
  const f = document.getElementById('f'), typeSel = document.getElementById('type');
  function toggle() {
    document.querySelectorAll('[data-for]').forEach(el => el.classList.toggle('hidden', !el.dataset.for.split(' ').includes(typeSel.value)));
  }
  typeSel.addEventListener('change', toggle); toggle();
  async function send(dryRun) {
    if (!f.reportValidity()) return;
    const data = Object.fromEntries(new FormData(f));
    // Only send fields that are visible for this event type.
    document.querySelectorAll('[data-for].hidden input, [data-for].hidden select').forEach(el => delete data[el.name]);
    data.dryRun = dryRun;
    if (data.type === 'session-revoked') { data.lastKnownIp = data.previousIp; delete data.previousIp; }
    document.getElementById('status').textContent = dryRun ? 'Signing...' : 'Sending...';
    const r = await fetch('/api/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    const j = await r.json();
    document.getElementById('out').classList.remove('hidden');
    if (j.error) { document.getElementById('status').textContent = 'Error: ' + j.error; return; }
    const d = j.delivery;
    document.getElementById('status').textContent = dryRun ? 'Signed (not sent).' : (d.ok ? 'Okta accepted the SET (202).' : 'Okta rejected the SET (' + d.status + ').');
    document.getElementById('resp').textContent = dryRun ? 'dry run' : 'HTTP ' + d.status + '\\n' + JSON.stringify(d.body, null, 2);
    document.getElementById('decoded').textContent = JSON.stringify(j.decoded, null, 2);
    document.getElementById('jwt').textContent = j.jwt;
  }
  f.addEventListener('submit', e => { e.preventDefault(); send(false); });
  document.getElementById('dry').addEventListener('click', () => send(true));
</script>
</body></html>`;
}
