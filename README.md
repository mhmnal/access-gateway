# Access Gateway

A small **Nginx + Node.js + SQLite** access gateway: a reverse proxy in front of an application,
**domain-locked sign-in**, role-based access, and every request — including failures — written to
an append-only audit trail.

A sanitised rebuild of a gateway I designed and ran for a university IT unit. All institutional
data, domains and credentials are removed; the demo domain is `example.edu`.

**Zero runtime dependencies.** Node 22 ships SQLite and scrypt, so the entire auth boundary is
readable in one sitting — no framework standing between you and the access checks.

```
14/14 smoke assertions passing
```

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
   browser          │              nginx :80/:443              │
  ─────────────►    │  reverse proxy · TLS · security headers   │
                    └───────────────┬──────────────────────────┘
                                    │ proxy_pass 127.0.0.1:3000
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │           node / http :3000              │
                    │  auth · domain lock · RBAC · audit write  │
                    └───────────────┬──────────────────────────┘
                                    │
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │              sqlite (WAL)                │
                    │   users · sessions · access_log          │
                    └──────────────────────────────────────────┘
```

| Layer | Choice | Why |
|---|---|---|
| Proxy | Nginx | terminates TLS; the app is never exposed directly |
| App | Node `http` + `node:sqlite` | minimal surface area for an auth boundary |
| Data | SQLite (WAL) | transactional, single-file, trivially auditable and backed up |

## Features

- **Domain-locked authentication** — sign-in accepted only for `ALLOWED_DOMAIN`, rejected
  server-side at the request handler. A client-side check would be decoration.
- **Role-based access** — `user` / `admin`, enforced per route; `/admin` returns 403 for a valid
  non-admin session (not a redirect, so the denial is explicit and logged).
- **Append-only audit trail** — every request records `email`, `method`, `route`, `status`,
  `client_ip` and `timestamp`, *before* the response is sent.
- **Sessions** — 32-byte random tokens, `HttpOnly` + `SameSite=Lax`, server-side with expiry so
  they can be revoked. JWTs were rejected deliberately: revocation matters more than statelessness
  at this scale.
- **Password hashing** — scrypt (N=16384, r=8, p=1), per-password salt, constant-time comparison.
- **Proxy isolation** — the app binds `127.0.0.1`; `server_tokens off`, dotfiles denied.

## Quick start

Requires **Node >= 22.5** (for `node:sqlite`). No `npm install` — there are no dependencies.

```bash
git clone https://github.com/mhmnal/<repo-name>.git
cd <repo-name>
cp .env.example .env          # set ALLOWED_DOMAIN, SEED_PASSWORD
npm run seed                  # creates user@example.edu and admin@example.edu
npm start                     # http://127.0.0.1:3000
```

Then verify the access rules:

```bash
node scripts/smoke.js
```

```
PASS  rejects foreign domain — got 403, expected 403
PASS  rejects wrong password — got 401, expected 401
PASS  admin blocks non-admin role — got 403, expected 403
PASS  session invalid after logout — got 302, expected 302
...
14 passed, 0 failed
```

The smoke test covers the cases that actually matter: unauthorised access, wrong-domain sign-in,
role escalation, and session invalidation after logout.

### Behind Nginx

```bash
sudo cp nginx/access-gateway.conf /etc/nginx/sites-available/access-gateway
sudo ln -s /etc/nginx/sites-available/access-gateway /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Set `PROXY_TLS=1` in `.env` once the proxy terminates TLS, so session cookies get `Secure`.

## Data model

```sql
users     (id, email UNIQUE, password_hash, role CHECK(user|admin), created_at)
sessions  (id TEXT PK, user_id → users, created_at, expires_at)
access_log(id, user_id, email, method, route, status, client_ip, created_at)
```

`access_log` is written by `audit()` in `db.js`. Nothing in the app updates or deletes from it.

## Notes on the 403 episode

The original deployment threw intermittent Nginx `403 Permission denied` errors. Cause: the
directory the app served sat under a path Nginx's worker user could not traverse. Fix: `755` on
the directory chain, `640` on the data file, and an explicit `deny all` for dotfiles so the rule
was visible rather than implied.

## What this is not

Not a hardened identity provider. It is a compact, readable reference for three patterns worth
knowing — **proxy isolation**, **server-side authorisation**, and **auditability** — deliberately
small enough to read in one sitting.

## License

MIT
