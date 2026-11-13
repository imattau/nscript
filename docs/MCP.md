# MCP server

`nscript-mcp` exposes NScript check, inspection, and dry-simulation workflows to MCP-compatible agents. It is general-purpose and does not know about a particular social network or Nostr application.

## Build and local use

Build the server and CLI from the repository root:

```sh
cargo build --release -p nscript-mcp -p nscript-cli
```

The default transport is stdio. The server finds `nscript` beside its own executable; set `NSCRIPT_CLI_PATH` if it is installed elsewhere. Both executables run with the MCP process user's permissions.

```json
{
  "mcpServers": {
    "nscript": {
      "command": "/path/to/nscript-mcp",
      "env": { "NSCRIPT_CLI_PATH": "/path/to/nscript" }
    }
  }
}
```

Install the published npm bundle on Linux x86_64 or macOS Apple Silicon with `npx -y nscript-mcp@0.3.5`. It bundles both the MCP server and CLI. The `nscript-mcp` command uses stdio by default.

## Tools

- **`nscript_check`** parses and statically checks source, returning compiler diagnostics and a success status.
- **`nscript_inspect`** returns a structured manifest with effects, resolved modules, operation calls, and publication trace.
- **`nscript_simulate_event`** sends a JSON event to the CLI simulator. It accepts optional `principal` (`--as`), declared scalar `inputs`, and `module_dirs`.
- **`nscript_test_event`** simulates an event and reports the dispatched handler count and per-handler event type, author, and tag filter trace. Principal-based predicates are resolved against its `principal` argument. Use it to diagnose events that match zero handlers. Unsupported handler predicate shapes fail checking with E2402, so they cannot silently widen a subscription. It accepts `principal` and `module_dirs`.

Simulation is dry: it does not connect to relays, publish events, or access signer keys. Operations without a simulator implementation are recorded and answered with declared placeholder values.

The server accepts source up to 1 MB and event JSON up to 256 KB. Temporary source files use owner-only permissions on Unix and are removed after use. Paths to temporary source files are redacted from CLI diagnostics.

## Timeouts and cancellation

CLI commands time out after 30 seconds by default. Set `NSCRIPT_MCP_TIMEOUT_SECS` to a positive integer to change the limit. On stdio, an MCP `notifications/cancelled` notification terminates the CLI process associated with that request. In HTTP mode, disconnecting the request stream terminates its CLI process.

## Module directories and filesystem access

`module_dirs` is an explicit list of local paths. For stdio clients, each path is passed to the NScript CLI with `-M`, which recursively reads `.nsm` modules under those directories using the MCP process user's filesystem permissions. Only provide paths the agent is allowed to read.

For HTTP mode, module paths must resolve beneath one of the directories in `NSCRIPT_MCP_ALLOWED_MODULE_ROOTS`, a path-separated list. This restriction applies to all HTTP MCP tools.

## Streamable HTTP

HTTP is opt-in:

```sh
NSCRIPT_MCP_BEARER_TOKEN='replace-with-a-secret' \
NSCRIPT_MCP_ALLOWED_ORIGINS='https://agent.example' \
nscript-mcp --http
```

The server binds to `127.0.0.1:8765` by default. Set `NSCRIPT_MCP_BIND` to change the address. Set `NSCRIPT_MCP_ALLOWED_HOSTS` to a comma-separated list of permitted Host header names when using a non-local hostname. Set `NSCRIPT_MCP_ALLOWED_ORIGINS` to a comma-separated list of permitted browser origins. Requests without an Origin header are permitted for native clients; permitted browser origins receive CORS headers. HTTP requires `NSCRIPT_MCP_BEARER_TOKEN`; every request must send it as a Bearer authorization token.

The transport accepts MCP POST requests at `/mcp` and returns either JSON or a request-scoped SSE response based on the client Accept header. It is intended for a trusted local environment or behind a TLS reverse proxy; the bearer token is a shared secret, not an OAuth authorization service.

## Scope

The server supports authoring and dry simulation. It does not expose `deploy` or any live network, signing, or package-mutation tool. A deployment host should grant capabilities through NScript's normal permission and host policies.
