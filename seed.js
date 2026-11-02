'use strict';
/**
 * Creates demo accounts. Idempotent — re-running will not duplicate users.
 *   node seed.js
 */
const fs = require('node:fs');
const path = require('node:path');

(function loadEnv() {
  const file = path.join(__dirname, '.env');
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (!(key in process.env)) process.env[key] = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
  }
})();

const { db, now } = require('./db');
const { hashPassword, ALLOWED_DOMAIN } = require('./auth');

const password = process.env.SEED_PASSWORD || 'demo1234';

const users = [
  { email: `user@${ALLOWED_DOMAIN}`, role: 'user' },
  { email: `admin@${ALLOWED_DOMAIN}`, role: 'admin' },
];

for (const u of users) {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(u.email);
  if (existing) {
    console.log(`exists  ${u.email}`);
    continue;
  }
  db.prepare('INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)')
    .run(u.email, hashPassword(password), u.role, now());
  console.log(`created ${u.email} (${u.role})`);
}

console.log(`\nPassword for all demo accounts: ${password}`);
