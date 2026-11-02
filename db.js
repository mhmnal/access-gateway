'use strict';
/**
 * Database layer. Node's built-in SQLite (Node >= 22) keeps the dependency
 * count at zero so the whole auth boundary stays readable.
 */
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'gateway.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);

db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    created_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS access_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    email      TEXT,
    method     TEXT NOT NULL,
    route      TEXT NOT NULL,
    status     INTEGER NOT NULL,
    client_ip  TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_access_log_created ON access_log(created_at);
`);

const now = () => new Date().toISOString();

/** Append-only audit write. Called before the response is sent. */
function audit({ userId = null, email = null, method, route, status, clientIp }) {
  db.prepare(
    `INSERT INTO access_log (user_id, email, method, route, status, client_ip, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(userId, email, method, route, status, clientIp, now());
}

module.exports = { db, audit, now, DB_PATH };
