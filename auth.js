'use strict';
/**
 * Authentication, sessions and the domain lock.
 * Everything here is server-side: the browser never decides who it is.
 */
const crypto = require('node:crypto');
const { db, now } = require('./db');

const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MINUTES || 480) * 60 * 1000;
const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'example.edu').toLowerCase();

// ---------------------------------------------------------------- passwords
// scrypt is built into Node, so no bcrypt dependency is needed.
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt.toString('hex')}$${derived.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, N, r, p, saltHex, hashHex] = stored.split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const derived = crypto.scryptSync(password, salt, expected.length, {
      N: Number(N), r: Number(r), p: Number(p),
    });
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- domain lock
function isAllowedDomain(email) {
  const at = String(email).toLowerCase().lastIndexOf('@');
  if (at === -1) return false;
  return String(email).toLowerCase().slice(at + 1) === ALLOWED_DOMAIN;
}

// ---------------------------------------------------------------- sessions
function createSession(userId) {
  const id = crypto.randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  db.prepare('INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(id, userId, now(), expires);
  return { id, expiresAt: expires };
}

function getSession(id) {
  if (!id) return null;
  const row = db
    .prepare(
      `SELECT s.id, s.user_id, s.expires_at, u.email, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id = ?`
    )
    .get(id);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    destroySession(id);
    return null;
  }
  return row;
}

function destroySession(id) {
  if (id) db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

// ---------------------------------------------------------------- cookies
const COOKIE_NAME = 'sid';

function parseCookies(header = '') {
  return Object.fromEntries(
    header
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const eq = part.indexOf('=');
        return [part.slice(0, eq), decodeURIComponent(part.slice(eq + 1))];
      })
  );
}

function sessionCookie(id, maxAgeMs = SESSION_TTL_MS) {
  // Secure is added automatically when the request arrived over TLS via the proxy.
  const parts = [
    `${COOKIE_NAME}=${id}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (process.env.PROXY_TLS === '1') parts.push('Secure');
  return parts.join('; ');
}

function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

module.exports = {
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
};
