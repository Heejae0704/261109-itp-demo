const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function page({ config, session, sessions, logoutLog, kicked }) {
  const user = session?.user;
  const logRows = logoutLog
    .map(
      (l) => `<tr><td>${esc(l.at.replace('T', ' ').slice(0, 19))}</td><td>${esc(JSON.stringify(l.body?.sub_id ?? l.body))}</td>
      <td class="${l.status === 204 ? 'ok' : 'bad'}">${esc(l.status)}</td><td>${esc(l.note)}</td></tr>`
    )
    .join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acme Portal</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --fg:#1c1f24; --muted:#5b6370; --line:#dde1e6; --accent:#0b7285; --ok:#2b8a3e; --bad:#c92a2a; --warn-bg:#fff4e6; --warn:#a14a00; }
  @media (prefers-color-scheme: dark) { :root { --bg:#14161a; --card:#1d2026; --fg:#e7e9ec; --muted:#9aa3ad; --line:#2e333b; --accent:#3bc9db; --ok:#69db7c; --bad:#ff8787; --warn-bg:#3a2a15; --warn:#ffc078; } }
  * { box-sizing:border-box; } body { margin:0; font:15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); }
  main { max-width: 900px; margin:0 auto; padding:24px 16px 64px; }
  h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:16px; margin:0 0 12px; }
  .muted { color:var(--muted); } .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px; margin-top:18px; }
  .btn { display:inline-block; padding:9px 16px; border:0; border-radius:6px; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; text-decoration:none; }
  .banner { background:var(--warn-bg); color:var(--warn); border-radius:8px; padding:12px 14px; margin-top:18px; font-weight:600; }
  dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 16px; margin:0; } dt { color:var(--muted); } dd { margin:0; word-break:break-all; }
  table { width:100%; border-collapse:collapse; font-size:13px; } td, th { text-align:left; padding:6px 8px; border-top:1px solid var(--line); vertical-align:top; word-break:break-word; }
  .ok { color:var(--ok); font-weight:600; } .bad { color:var(--bad); font-weight:600; } .wrap { overflow-x:auto; }
</style></head>
<body><main>
  <h1>Acme Portal</h1>
  <div class="muted">Demo app signed in with Okta (OIDC). Supports Okta Universal Logout.</div>
  ${kicked ? '<div class="banner">Your session was ended by Okta Universal Logout (risk detected).</div>' : ''}

  <section class="card">
    ${
      user
        ? `<h2>Signed in</h2>
           <dl><dt>Name</dt><dd>${esc(user.name)}</dd><dt>Email</dt><dd>${esc(user.email)}</dd>
           <dt>Subject</dt><dd><code>${esc(user.sub)}</code></dd><dt>Issuer</dt><dd><code>${esc(user.iss)}</code></dd>
           <dt>Session started</dt><dd>${esc(session.createdAt)}</dd></dl>
           <form method="post" action="/logout" style="margin-top:14px"><button class="btn">Sign out</button></form>
           <p class="muted" style="margin-bottom:0">This page checks your session every 3 seconds. When Okta sends Universal Logout, you'll be signed out here automatically.</p>`
        : `<h2>Not signed in</h2><a class="btn" href="/login">Sign in with Okta</a>`
    }
  </section>

  <section class="card">
    <h2>Okta app settings</h2>
    <dl>
      <dt>Sign-in redirect URI</dt><dd><code>${esc(config.baseUrl + config.redirectPath)}</code></dd>
      <dt>Sign-out redirect URI</dt><dd><code>${esc(config.baseUrl)}/</code></dd>
      <dt>Logout endpoint URL</dt><dd><code>${esc(config.baseUrl + config.logoutPath)}</code></dd>
      <dt>Issuer</dt><dd><code>${esc(config.issuer)}</code></dd>
      <dt>Active app sessions</dt><dd>${sessions.length}</dd>
    </dl>
  </section>

  <section class="card">
    <h2>Universal Logout requests from Okta</h2>
    <div class="wrap"><table><thead><tr><th>Time (UTC)</th><th>sub_id</th><th>Result</th><th>Note</th></tr></thead>
    <tbody>${logRows || '<tr><td colspan="4" class="muted">None received yet.</td></tr>'}</tbody></table></div>
  </section>
</main>
${
  user
    ? `<script>
  setInterval(async () => {
    try { const r = await fetch('/api/me'); const j = await r.json(); if (!j.authenticated) location.href = '/?kicked=1'; } catch {}
  }, 3000);
</script>`
    : ''
}
</body></html>`;
}
