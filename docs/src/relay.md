# Relay and remote control

The relay streams session events to a dashboard over an outbound WebSocket:
your machine dials out, so no inbound port opens on your side.

## Client

```bash
freedas relay start              # daemonize
freedas relay start --foreground
freedas relay stop
freedas relay share <sessionID>  # expose a session to the dashboard
freedas relay unshare <sessionID>
freedas relay status
```

`/remote` (alias `/rc`) inside the TUI starts the daemon if needed and shares
the current session.

`relay start` re-executes itself with `--foreground` and writes logs to
`<state>/relay.log`; `share`/`unshare` update `<state>/relay.json`, which the
daemon polls every 2 seconds. `relay status` prints `running`/`stopped` and
the shared session IDs.

Connection details:

- URL: `FREEDAS_RELAY_URL`, default `ws://127.0.0.1:4098/ws`.
- Token: `FREEDAS_RELAY_TOKEN`, else the stored `relay` credential.
- Machine id: generated once into `<config>/machine-id` (mode 0600).

## Frames

JSON frames tagged `type`:

- Client → server: `hello` (`machine_id`, `version`, `scope`, `token`), `heartbeat` every 15 s, `event` (`session_id`, monotonic `seq`, event payload), `share`/`unshare`, `permission` (`permission_id`, `action`, `resource`), `prompt`, `abort`, `error`.
- Server → client: `prompt` (`session_id`, `text`), `abort`, `permission_reply`, `error`.

Frames over 1 MiB are replaced by a marker event. The daemon mirrors the
local server's SSE stream as `event` frames and raises `permission` frames
when a `permission.asked` appears; a `permission_reply` answers the ask.

## Relay server

`freedas-relay-server` is the self-hosted counterpart:

```bash
freedas-relay-server --token <token>           # ws://127.0.0.1:8082/ws
freedas-relay-server --host 0.0.0.0 --token <token>
```

Refuses to bind a non-loopback host without `--token` (env
`FREEDAS_RELAY_TOKEN`). It tracks machine presence in memory, fans events out
to connected dashboards, and stores no transcript. The dashboard API needs
the same bearer token as the `hello` frame:

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health |
| GET | `/ws` | Machine WebSocket upgrade |
| GET | `/events` | SSE fan-out to dashboards (`?token=` or `Authorization`) |
| GET | `/machines` | Connected machines and exposed session counts |
| GET | `/sessions` | Every exposed session |
| GET | `/sessions/{id}/summary` | Latest usage totals |
| POST | `/sessions/{id}/prompt` | Forward a prompt to the owning machine |
| POST | `/sessions/{id}/abort` | Interrupt the run |
| POST | `/sessions/{id}/permission` | Answer a permission ask |

Stopping the daemon (`relay stop`) removes the machine from the dashboard and
closes the socket.
