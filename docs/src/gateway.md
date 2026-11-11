# Gateway

`freedas-gateway` is an OpenAI-compatible proxy that meters requests into the
workspace wallet, enforces budgets before dispatch, and routes
`freedas/auto`/`freedas/auto-cheap` server-side. It needs the control-plane
PostgreSQL database for tokens and billing.

## Running

```bash
DATABASE_URL=postgres://... freedas-gateway \
  --upstream https://api.openai.com/v1 \
  --provider-key anthropic=sk-ant-... \
  --port 8081
```

Flags:

- `--upstream` - OpenAI-compatible base URL (default `https://api.openai.com/v1`). Precedence: flag, then `FREEDAS_GATEWAY_UPSTREAM`, then the deprecated `FREEDAS_UPSTREAM_URL` (warns), then the default.
- `--database-url` / `DATABASE_URL` - required unless `--insecure-no-auth`.
- `--provider-key PROVIDER=KEY` - upstream credential per provider, repeatable. Provider env vars are the fallback: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`.
- `--insecure-no-auth` - accept any non-empty bearer; no metering or budgets. Local testing only.
- `--hostname`, `--port` (defaults `127.0.0.1:8081`).

Without `--database-url` and without `--insecure-no-auth` the binary refuses
to start.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/models` | Models available to the workspace (only providers with a configured upstream key) |
| POST | `/v1/chat/completions` | Stream or non-stream chat |
| POST | `/v1/embeddings` | Embeddings for the allowlisted models only (`text-embedding-3-small`, `text-embedding-3-large`, `text-embedding-ada-002`), metered at a fixed rate |

Auth is `Authorization: Bearer <workspace token>`; the token hash resolves to
a workspace and user. Optional `X-Freedas-Session` ties metering to a session.
Sandbox-scoped tokens can only call the model endpoints, not the rest of the
API.

## Routing `freedas/auto`

When the requested model is `freedas/auto` or `freedas/auto-cheap`, the
gateway runs the same router against the request's last user message:
`auto` classifies as the build agent, `auto-cheap` as plan-quick (cheap tier,
lower floor). The routed model replaces `model` in the forwarded request and
comes back in the `X-Freedas-Model` response header. Concrete model names
pass through unchanged. The gateway uses static quality priors (no learned
history, no exploration).

## Metering and budgets

Before dispatch, the estimated cost is reserved against the workspace
balance; an insufficient balance returns `402`. On stream end the actual
usage from the upstream `usage` chunk (or a token estimate) reconciles the
ledger: the reservation is released and real cost is recorded as a
`usage_events` row plus a `wallet_ledger` debit. A client that disconnects
mid-stream still gets metered — metering fires on body drop as well as
stream end — and a nonzero cost never debits less than one microdollar, so
dust-priced requests are not free. A post-metering negative balance is
logged at error level for alerting.

## Client use

```bash
freedas providers login freedas   # device flow via FREEDAS_CONTROL_URL, or paste a token
freedas run "task"                # model = freedas/auto goes to the gateway
```

The CLI's `freedas` provider sends chat-completions requests to
`FREEDAS_GATEWAY_URL` (default `http://127.0.0.1:8081/v1`) with the stored
credential and the workspace header.
