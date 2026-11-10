# Control plane

`freedas-control` is the self-hosted account and billing service behind the
gateway, reviews, sandboxes, the skill registry, and the dashboard. It needs
PostgreSQL; there is no SQLite backend.

## Running

```bash
DATABASE_URL=postgres://... freedas-control \
  --base-url https://app.example.com \
  --hostname 127.0.0.1 --port 8080
```

- `--database-url` / `DATABASE_URL` (required)
- `--base-url` / `FREEDAS_BASE_URL` - public URL used in install links and callbacks (default `http://127.0.0.1:8080`)
- `--hostname` (default `127.0.0.1`), `--port` (default `8080`)

Migrations run at startup. A background task reaps sandboxes that stop
heartbeating for 60 s and marks them failed.

The dashboard SPA is served at `/`, `/me`, and `/org/{slug}`.

## Auth

- `POST /auth/register` - create a local user (email + password, argon2 hash).
- `POST /auth/login` - returns an API token.
- `GET /auth/me` - current user.
- `GET /auth/oidc/start`, `GET /auth/oidc/callback` - OIDC login when `FREEDAS_OIDC_ISSUER` and `FREEDAS_OIDC_CLIENT_ID` are set (plus `FREEDAS_OIDC_CLIENT_SECRET` when required); JIT user creation on first login.
- SCIM 2.0 at `/scim/v2/Users` and `/scim/v2/Groups` behind `FREEDAS_SCIM_TOKEN` bearer auth: list, create, PATCH, delete users; list groups.
- Device flow for the CLI: `POST /device/code` issues a user code, `GET /device` is the approval page, `POST /device/approve` approves, `POST /device/token` returns the token the CLI polls for. `freedas providers login freedas` uses this when `FREEDAS_CONTROL_URL` is set.

API tokens authenticate as `Authorization: Bearer <token>`; the DB stores
only the SHA-256 hash, the plaintext shows once at creation. Sandbox-scoped
tokens (`sandbox:<id>`) are restricted to their own sandbox endpoints, `/v1`
proxy, and a few read-only routes.

## Resources

| Endpoint | Purpose |
|---|---|
| `GET/POST /workspaces`, `GET/PATCH /workspaces/{slug}` | Workspaces and settings |
| `GET/POST /workspaces/{slug}/members` | Membership |
| `GET/POST /workspaces/{slug}/teams`, `POST /workspaces/{slug}/teams/{id}/members` | Teams |
| `GET/POST /workspaces/{slug}/budgets` | Workspace/user/team budgets, monthly or total |
| `GET /workspaces/{slug}/invoices`, `POST /workspaces/{slug}/invoices/generate` | Monthly usage invoices |
| `GET/PATCH /workspaces/{slug}/settings` | `sandboxes_enabled`, compute rate, session limit, SSO policy |
| `GET /usage`, `GET /usage/summary` | Usage events and totals |
| `GET /wallet`, `POST /wallet/credits` | Ledger balance and manual credits |
| `GET/POST /tokens`, `DELETE /tokens/{id}` | API tokens (scoped, expirable, revocable) |
| `GET/POST /reviews`, `GET /reviews/{id}`, `POST /reviews/{id}/retry`, `GET /reviews/analytics` | Review queue and analytics |
| `GET/PATCH /reviews/config` | Per-workspace review policy |
| `GET/POST /sandboxes`, `GET /sandboxes/{id}`, `POST /sandboxes/{id}/stop`, `POST /sandboxes/{id}/heartbeat`, `POST /sandboxes/{id}/token` | Cloud sandbox lifecycle |
| `GET /github/install`, `GET/POST /github/installations`, `DELETE /github/installations/{id}`, `GET/PATCH /github/installations/{id}/repositories`, `POST /github/webhook`, `GET /github/pulls` | GitHub App install/link and webhook intake |
| `GET/POST /registry/skills`, `GET/POST /registry/skills/{name}` | Team skill registry |
| `GET/POST /sessions` | Session metadata posted by the CLI |

## Billing model

`wallet_ledger` is append-only (credits positive, usage negative). Model
calls, sandbox compute, and review cost all meter into the wallet of the
session's workspace. Budgets scope to workspace, user, or team, monthly or
total. The gateway enforces the balance before dispatch; see
[Gateway](./gateway.md).

## Webhook security

`POST /github/webhook` verifies `X-Hub-Signature-256` against
`FREEDAS_GITHUB_WEBHOOK_SECRET`, records the delivery id for replay
protection, then enqueues a `reviews` row. See [Reviews](./reviews.md).
