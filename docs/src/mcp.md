# MCP servers

Freedas connects to Model Context Protocol servers over stdio (local) or
streamable HTTP (remote), using the `rmcp` client. Tools appear to the model
as `<server>_<tool>`; prompts become slash commands `/<server>:<prompt>`.

## Configure

In `freedas.json(c)`:

```jsonc
{
  "mcp": {
    "linear": {
      "type": "remote",
      "url": "https://mcp.linear.app/mcp",
      "oauth": true,
      "headers": { "X-Team": "core" }
    },
    "local": {
      "type": "local",
      "command": ["npx", "-y", "@acme/mcp-server"],
      "cwd": ".",
      "environment": { "ACME_TOKEN": "{env:ACME_TOKEN}" },
      "timeout_ms": 30000
    }
  }
}
```

Per-server keys: `type`, `url`, `command`, `cwd`, `environment`, `headers`,
`oauth`, `disabled`, `timeout_ms` (default 30000).

Or let the CLI write the config for you:

```bash
freedas mcp add linear --url https://mcp.linear.app/mcp
freedas mcp add local -- npx -y @acme/mcp-server
```

Both forms write the `mcp` map into the project `.freedas/freedas.json`.

## Manage

```bash
freedas mcp list            # name, state, tool/prompt counts
freedas mcp auth <name>     # OAuth for remote, else store a token
freedas mcp logout <name>   # remove stored credentials
freedas mcp debug <name>    # connect, list tools and prompts, last error
```

`mcp auth` runs the OAuth flow (protected-resource and authorization-server
discovery, PKCE, loopback redirect) and stores the tokens as `mcp-<name>` /
`mcp-<name>-refresh` credentials. If OAuth is unavailable it falls back to a
token prompt; `MCP_<NAME>_TOKEN` supplies one non-interactively.

`mcp debug` prints the handshake result, the tool list, and the prompt list - 
never credentials.

## In a session

- Tools: `linear_create_issue` style names (server and tool sanitized to
  `[a-zA-Z0-9_]`). Each call follows the permission action `<server>_<tool>`
  with resource `*`; add rules like
  `{ "action": "linear_*", "resource": "*", "effect": "ask" }` to prompt.
- Prompts: `/<server>:<prompt>` runs the server's prompt template.
- `/mcps` toggles individual servers for the session without editing config;
  `Alt+M` opens the same picker. `disabled: true` in config keeps a server
  connected-out until enabled.

Connection failures surface in `mcp list` as the server's `error` state; the
client reconnects with backoff on the next call.
