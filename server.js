'use strict';
/**
 * Zero-dependency access gateway.
 * Nginx terminates the connection and proxies here; this process binds 127.0.0.1 only.
 */
const fs = require('node:fs');
const path = require('node:path');

// Load .env before any module reads process.env.
(function loadEnv() {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (!(key in process.env)) process.env[key] = value;
  }
})();

const http = require('node:http');
const { db, audit } = require('./db');
const {
  ALLOWED_DOMAIN,
  COOKIE_NAME,
  hashPassword,
  verifyPassword,
  isAllowedDomain,
  createSession,
  getSession,
  destroySession,
  parseCookies,
  sessionCookie,
  clearCookie,
} = require('./auth');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function layout(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — Access Gateway</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         background: #f6f7f9; color: #1b1f24; }
  main { max-width: 720px; margin: 8vh auto; padding: 0 20px; }
  .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 28px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 28px 0 8px; color: #444; }
  p.sub { margin: 0 0 22px; color: #667; font-size: 13px; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 5px; }
  input { width: 100%; padding: 10px 12px; border: 1px solid #cfd4da; border-radius: 7px;
          font-size: 14px; background: #fff; color: inherit; }
  button { margin-top: 18px; width: 100%; padding: 11px; border: 0; border-radius: 7px;
           background: #16610f; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; }
  button:hover { background: #124d0c; }
  .alert { padding: 10px 12px; border-radius: 7px; font-size: 13px; margin-bottom: 16px; }
  .alert.err { background: #fdecec; color: #8a1c1c; border: 1px solid #f5c6c6; }
  .alert.ok { background: #eaf6e8; color: #1d5c16; border: 1px solid #c8e5c3; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #eceff2; }
  th { color: #667; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  .meta { font-size: 13px; color: #667; }
  form.inline { display: inline; }
  a { color: #16610f; }
  .logout { background: none; border: 0; color: #16610f; cursor: pointer; padding: 0;
            font-size: 13px; text-decoration: underline; margin-top: 0; width: auto; }
  .logout:hover { background: none; }
</style></head><body><main>${body}</main></body></html>`;
}

const loginPage = (error = '') =>
  layout(
    'Sign in',
    `<div class="card">
      <h1>Access Gateway</h1>
      <p class="sub">Restricted to <strong>@${esc(ALLOWED_DOMAIN)}</strong> accounts.</p>
      ${error ? `<div class="alert err">${esc(error)}</div>` : ''}
      <form method="POST" action="/login">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="username"
               placeholder="you@${esc(ALLOWED_DOMAIN)}" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Sign in</button>
      </form>
    </div>`
  );

function dashboardPage(user) {
  const rows = db
    .prepare(
      `SELECT method, route, status, client_ip, created_at
         FROM access_log WHERE user_id = ? ORDER BY id DESC LIMIT 10`
    )
    .all(user.user_id);

  const body = rows.length
    ? `<table><thead><tr><th>Method</th><th>Route</th><th>Status</th><th>IP</th><th>When</th></tr></thead>
       <tbody>${rows
         .map(
           (r) =>
             `<tr><td>${esc(r.method)}</td><td>${esc(r.route)}</td><td>${esc(r.status)}</td>` +
             `<td>${esc(r.client_ip)}</td><td>${esc(r.created_at)}</td></tr>`
         )
         .join('')}</tbody></table>`
    : '<p class="meta">No activity recorded yet.</p>';

  return layout(
    'Dashboard',
    `<div class="card">
      <h1>Signed in</h1>
      <p class="sub">${esc(user.email)} · role: ${esc(user.role)}</p>
      ${user.role === 'admin' ? '<div class="alert ok">Admin access granted — <a href="/admin">view full audit log</a></div>' : ''}
      <h2>Your recent access</h2>
      ${body}
      <form class="inline" method="POST" action="/logout">
        <button class="logout" type="submit">Sign out</button>
      </form>
    </div>`
  );
}

function adminPage(user) {
  const rows = db
    .prepare(
      `SELECT email, method, route, status, client_ip, created_at
         FROM access_log ORDER BY id DESC LIMIT 25`
    )
    .all();

  return layout(
    'Audit log',
    `<div class="card">
      <h1>Audit log</h1>
      <p class="sub">Last 25 entries · signed in as ${esc(user.email)}</p>
      <table><thead><tr><th>Email</th><th>Method</th><th>Route</th><th>Status</th><th>IP</th><th>When</th></tr></thead>
      <tbody>${rows
        .map(
          (r) =>
            `<tr><td>${esc(r.email ?? '—')}</td><td>${esc(r.method)}</td><td>${esc(r.route)}</td>` +
            `<td>${esc(r.status)}</td><td>${esc(r.client_ip)}</td><td>${esc(r.created_at)}</td></tr>`
        )
        .join('')}</tbody></table>
      <p style="margin-top:18px"><a href="/dashboard">← back</a></p>
    </div>`
  );
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e5) req.destroy();
    });
    req.on('end', () => resolve(data));
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const route = url.pathname;
  const ip = clientIp(req);
  const cookies = parseCookies(req.headers.cookie);
  const session = getSession(cookies[COOKIE_NAME]);

  const send = (status, html, headers = {}) => {
    audit({
      userId: session?.user_id ?? null,
      email: session?.email ?? null,
      method: req.method,
      route,
      status,
      clientIp: ip,
    });
    res.writeHead(status, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      ...headers,
    });
    res.end(req.method === 'HEAD' ? undefined : html);
  };

  const redirect = (location, headers = {}) => {
    audit({
      userId: session?.user_id ?? null,
      email: session?.email ?? null,
      method: req.method,
      route,
      status: 302,
      clientIp: ip,
    });
    res.writeHead(302, { Location: location, ...headers });
    res.end();
  };

  try {
    if (route === '/healthz') {
      return send(200, 'ok');
    }

    if (route === '/' && req.method === 'GET') {
      return redirect(session ? '/dashboard' : '/login');
    }

    if (route === '/login' && req.method === 'GET') {
      return send(200, session ? dashboardPage(session) : loginPage());
    }

    if (route === '/login' && req.method === 'POST') {
      const body = new URLSearchParams(await readBody(req));
      const email = String(body.get('email') || '').trim().toLowerCase();
      const password = String(body.get('password') || '');

      // Domain lock is enforced here, server-side. A client-side check is decoration.
      if (!isAllowedDomain(email)) {
        return send(403, loginPage(`Sign-in is restricted to @${ALLOWED_DOMAIN} accounts.`));
      }

      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (!user || !verifyPassword(password, user.password_hash)) {
        return send(401, loginPage('Invalid email or password.'));
      }

      const s = createSession(user.id);
      return redirect('/dashboard', {
        'Set-Cookie': sessionCookie(s.id),
      });
    }

    if (route === '/logout' && req.method === 'POST') {
      destroySession(cookies[COOKIE_NAME]);
      return redirect('/login', { 'Set-Cookie': clearCookie() });
    }

    if (route === '/dashboard' && req.method === 'GET') {
      if (!session) return redirect('/login');
      return send(200, dashboardPage(session));
    }

    if (route === '/admin' && req.method === 'GET') {
      if (!session) return redirect('/login');
      if (session.role !== 'admin') return send(403, loginPage('Admin role required.'));
      return send(200, adminPage(session));
    }

    return send(404, loginPage('Not found.'));
  } catch (err) {
    console.error(err);
    return send(500, loginPage('Something went wrong.'));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`access-gateway listening on http://${HOST}:${PORT} (domain lock: @${ALLOWED_DOMAIN})`);
});
