#!/usr/bin/env node
'use strict';
/**
 * Smoke test — exercises every route and asserts the access rules hold.
 * Start the server first (`npm start`), then: `node scripts/smoke.js`
 */
const BASE = process.env.BASE_URL || 'http://127.0.0.1:3000';
const PASSWORD = process.env.SEED_PASSWORD || 'demo1234';
const DOMAIN = process.env.ALLOWED_DOMAIN || 'example.edu';

let pass = 0;
let fail = 0;

function check(name, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name} — got ${actual}, expected ${expected}`);
  ok ? pass++ : fail++;
}

async function req(pathname, opts = {}) {
  const res = await fetch(BASE + pathname, { redirect: 'manual', ...opts });
  return res;
}

function loginBody(email, password) {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ email, password }).toString(),
  };
}

(async () => {
  check('health check', (await req('/healthz')).status, 200);
  check('login page renders', (await req('/login')).status, 200);
  check('dashboard blocks anonymous', (await req('/dashboard')).status, 302);
  check('admin blocks anonymous', (await req('/admin')).status, 302);

  check(
    'rejects foreign domain',
    (await req('/login', loginBody('someone@gmail.com', PASSWORD))).status,
    403
  );
  check(
    'rejects wrong password',
    (await req('/login', loginBody(`user@${DOMAIN}`, 'wrong-password'))).status,
    401
  );

  const userLogin = await req('/login', loginBody(`user@${DOMAIN}`, PASSWORD));
  check('accepts valid user login', userLogin.status, 302);
  const userCookie = (userLogin.headers.get('set-cookie') || '').split(';')[0];
  check('issues a session cookie', Boolean(userCookie.startsWith('sid=')), true);

  const dashboard = await req('/dashboard', { headers: { cookie: userCookie } });
  check('dashboard allows signed-in user', dashboard.status, 200);

  const userAdmin = await req('/admin', { headers: { cookie: userCookie } });
  check('admin blocks non-admin role', userAdmin.status, 403);

  const adminLogin = await req('/login', loginBody(`admin@${DOMAIN}`, PASSWORD));
  const adminCookie = (adminLogin.headers.get('set-cookie') || '').split(';')[0];
  check('admin can read audit log', (await req('/admin', { headers: { cookie: adminCookie } })).status, 200);

  const logout = await req('/logout', { method: 'POST', headers: { cookie: userCookie } });
  check('logout redirects', logout.status, 302);
  check(
    'session invalid after logout',
    (await req('/dashboard', { headers: { cookie: userCookie } })).status,
    302
  );

  check('unknown route returns 404', (await req('/nope')).status, 404);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
