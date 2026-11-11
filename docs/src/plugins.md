# Plugins

Plugins extend Freedas with hooks, tools, TUI commands, and auth or workspace
adapters. Three runtimes are supported: WASM, JavaScript/TypeScript, and
process sidecars.

## Formats

- **WASM** (`.wasm`) - runs in a wasmtime store with no WASI and no host imports. It cannot read the filesystem, open sockets, or see the environment; each call is bounded by a fuel budget and a 64 MiB linear-memory cap.
- **JS/TS** (`.js`, `.ts`, `.mjs`, `.cjs`) - runs in QuickJS with only the `freedas` global, a 64 MiB memory cap, and a 2-second wall-clock limit per call. No Node.js APIs or native addons.
- **Process** - an executable speaking JSON-RPC over stdio. It is trusted code: it runs only after its file hash is recorded in `<data>/trusted_plugins.json`, which requires `FREEDAS_PLUGIN_TRUST=1` on first load and again whenever the file changes. The process gets a cleared environment plus a small allowlist (`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TMPDIR`, `TERM`) and a 5-second handshake.

## Discovery

A plugin lives in `<project>/.freedas/plugins/` or
`~/.config/freedas/plugins/` as a `.wasm`/`.js`/`.ts` file, a directory
containing one, or a `freedas-plugin.json` manifest naming the entry file.
Project plugins and `plugin` config entries resolve only in a trusted
project (`trust_project_code`); hash trust is re-verified at load time, and
`FREEDAS_PLUGIN_TRUST_FILE` relocates the trust store for CI isolation.

The `plugin` config key enables plugins:

```jsonc
{
  "plugin": [
    "@acme/freedas-plugin",                          // npm package
    "./plugins/company-auth.wasm",                   // local file
    ["./plugins/reviewer.ts", { "strict": true }],   // path + options tuple
    { "package": "./plugins/reviewer", "options": {} }
  ]
}
```

Local paths resolve relative to the config file. npm names are resolved
through `https://registry.npmjs.org` (override `FREEDAS_NPM_REGISTRY` for a
mirror), the tarball is integrity-checked, and the package is extracted to
`~/.local/share/freedas/plugins/<name>@<version>/`. The package's
`freedas` field names the entry point.

## Hooks

Available hooks: `session.start`, `session.end`, `prompt`, `tool.before`,
`tool.after`, `model.request`, `model.response`, `permission.ask`,
`gate.result`.

A hook receives a JSON payload and may return JSON; the host validates the
result. Errors are logged; a plugin that fails three hooks in a row is
disabled for the rest of the session. Hooks run in plugin load order.

## CLI

```bash
freedas plugin <module>          # install an npm package or local file into project config
freedas plugin <module> --global # write the spec to the global config
freedas plugin list              # specs currently configured
freedas plugin remove <name>     # remove spec and installed package dir
freedas plugin update [name]     # refresh installed npm plugin(s)
```

`plugin <module>` downloads and verifies the package, then appends the spec
to `.freedas/freedas.json` (or the global file with `--global`).

## Trust and safety summary

- WASM has no ambient capabilities.
- JS has a memory and time cap and only the `freedas` global.
- Process plugins are the only runtime with real OS access; they require an
  explicit hash trust (`FREEDAS_PLUGIN_TRUST=1`) that is re-checked whenever
  the file changes.
