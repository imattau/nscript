# MCP server

`nscript-mcp` exposes NScript checking, inspection, dry simulation, and WASM-sandboxed execution to MCP-compatible agents. It is general-purpose and does not know about a particular social network or Nostr application.

## Build and local use

Build the server and CLI from the repository root:

```sh
cargo build --release -p nscript-mcp -p nscript-cli
cargo build --release --target wasm32-unknown-unknown -p nscript-wasm
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

Install the published npm bundle on Linux x86_64/arm64, macOS Apple Silicon, or Windows x64/arm64 with `npx -y nscript-mcp@0.3.12`. It bundles the MCP server, CLI, and WASM guest. The `nscript-mcp` command uses stdio by default.

The MCP server loads `nscript_wasm.wasm` beside its executable. For manual installs, copy `target/wasm32-unknown-unknown/release/nscript_wasm.wasm` beside `nscript-mcp`, or set `NSCRIPT_WASM_PATH`. The guest has no WASI imports and runs with a 16 MiB memory limit and a 250 million fuel default. Administrators may set `NSCRIPT_MCP_WASM_FUEL` to a positive value up to 1 billion.

## Tools

- **`nscript_check`** parses and statically checks source, returning compiler diagnostics and a success status.
- **`nscript_inspect`** returns a structured manifest with effects, resolved modules, operation calls, and publication trace.
- **`nscript_simulate_event`** sends a JSON event to the CLI simulator. It accepts optional `principal` (`--as`), declared scalar `inputs`, and `module_dirs`.
- **`nscript_test_event`** simulates an event and reports the dispatched handler count and per-handler event type, author, and tag filter trace. Principal-based predicates are resolved against its `principal` argument. Use it to diagnose events that match zero handlers. Unsupported handler predicate shapes fail checking with E2402, so they cannot silently widen a subscription. It accepts `principal`, declared scalar `inputs`, and `module_dirs`.
- **`nscript_execute`** runs startup logic or delivers one event inside the WASM guest. It returns logs, operation traces, storage, failures, and each simulated publication's lowered wire tags. This tool is sandboxed and does not access real relays, signing keys, or live operation hosts. It accepts `principal`, declared scalar `inputs`, and `module_dirs`.
- **`nscript_package_publish`** creates a verified `.npk` from source and its resolved local module closure, then publishes it through npack. Set an explicit SemVer version on every release.
- **`nscript_package_search`** searches for packages that provide `nscript-program`; **`nscript_package_resolve`** resolves release metadata; **`nscript_package_install`**, **`nscript_package_update`**, **`nscript_package_list`**, and **`nscript_package_remove`** manage the current user's npack prefix. Install, update, and remove require the target release to declare `nscript-program` and obey npack's existing trust policy.
- **`nscript_execute_live`** is an explicit one-cycle live `nscript deploy` call. Supply `confirm_live: true`; the source can publish and handlers may process events from selected relays. Synthetic event injection is not supported in live mode.
- **`nscript_session_start`**, **`nscript_session_status`**, and **`nscript_session_stop`** manage long-running relay-backed deploy processes. Starting requires `confirm_live: true`. Active sessions are recovered when the MCP server restarts.

For live execution and sessions, `principal` can still be supplied explicitly. If exactly one configured signer is selected, its NIP-46 `get_public_key` identity supplies `me` automatically. With multiple signers, set `principal_signer` to one of the selected signer references.

Simulation and WASM execution are dry: they do not connect to relays, publish events, or access signer keys. Operations without a simulator implementation are recorded and answered with declared placeholder values. Live tools use the existing `nscript deploy` runtime and its native relay and NIP-46 adapters; they do not run inside the sandboxed WASM guest. Module operations stay simulated unless the server configures an operation command.

## Live execution and sessions

Live execution is disabled unless the server administrator opts in and configures its hosts:

```sh
NSCRIPT_MCP_LIVE_ENABLED=true \
NSCRIPT_MCP_RELAYS='["wss://relay.example"]' \
NSCRIPT_MCP_ALLOWED_RELAYS='["wss://relay.example"]' \
NSCRIPT_MCP_SIGNERS='{"bot":"bunker://…"}' \
NSCRIPT_MCP_INPUTS='{"bot-token":"…"}' \
NSCRIPT_MCP_OPERATION_COMMAND='/path/to/operation-host' \
NSCRIPT_MCP_STATE_DIR='/var/lib/nscript-mcp' \
nscript-mcp
```

`NSCRIPT_MCP_RELAYS`, `NSCRIPT_MCP_SIGNERS`, and `NSCRIPT_MCP_INPUTS` are JSON arrays/maps. Tool calls may select configured relay URLs, signer names, and input references; callers cannot supply raw signer URIs or an operation-command path. If `NSCRIPT_MCP_ALLOWED_RELAYS` is omitted, only the relays in `NSCRIPT_MCP_RELAYS` are permitted. Signer URIs and referenced input values are passed to the CLI through environment variables and are not written into session records or process arguments. Durable sessions reject raw per-call inputs whose names look secret-bearing; configure those values in `NSCRIPT_MCP_INPUTS` and pass `input_refs`, for example `{"api_token":"bot-token"}`. Non-sensitive raw inputs remain supported and are persisted as part of the session definition.

Sessions persist their source, selected relay URLs, signer names, inputs, module paths, logs, and NScript state under `NSCRIPT_MCP_STATE_DIR` (or the platform state directory). Session files and source files are owner-only on Unix. After a restart, the server reattaches to a still-running deploy process or starts it again using current server configuration. Restarted processes restore the CLI's durable `FileStorage` values and idempotency claims; they do not restore an exact relay cursor. Repeated relay history is filtered by persisted idempotency claims.

### Event webhooks for durable sessions

Durable sessions can forward successfully matched events to a local agent runtime
by setting both `NSCRIPT_MCP_EVENT_WEBHOOK_URL` and
`NSCRIPT_MCP_EVENT_WEBHOOK_TOKEN` in the MCP server environment. The URL must use
loopback HTTP. The deploy process sends a bearer-authenticated JSON POST after a
handler completes. Its body contains the Nostr event `id`, `pubkey`, `kind`,
`created_at`, `content`, and `tags` fields. Failed deliveries are retried and,
when a durable `--state-dir` is configured, written to the session's private
event webhook outbox for retry on the next polling cycle. Consumers should
deduplicate by event ID because an acknowledged request can be retried if the
connection fails before the acknowledgement is received.

The `nscript_execute_live` and session tools have live side effects. Use them only on a server whose relay, signer, and operation-host configuration is intended for the requesting MCP clients.

The server accepts source up to 1 MB and event JSON up to 256 KB. Temporary source files use owner-only permissions on Unix and are removed after use. Paths to temporary source files are redacted from CLI diagnostics.

## Timeouts and cancellation

CLI commands time out after 30 seconds by default. Set `NSCRIPT_MCP_TIMEOUT_SECS` to a positive integer to change the limit. On stdio, an MCP `notifications/cancelled` notification terminates the CLI process associated with that request. In HTTP mode, disconnecting the request stream terminates its CLI process.

## Npack package tools

Package tools are disabled unless the server process sets `NSCRIPT_MCP_NPACK_ENABLED=true`. Install npack separately and set `NSCRIPT_MCP_NPACK_PATH` when it is not on `PATH`. Npack uses its normal local config for relays, artifact storage, and publisher trust. Set `NSCRIPT_MCP_NPACK_PUBLISHER` to the dedicated publisher public key registered in that same OS user context with `npack`; the private key stays in npack's credential store and is never accepted as an MCP argument. Package operations time out after 120 seconds by default; set `NSCRIPT_MCP_NPACK_TIMEOUT_SECS` to change this.

Publishing builds and checks the source, creates and verifies a lockfile, includes only custom modules resolved by the program, packs a temporary archive, hashes it, and asks npack to publish it. Temporary staging directories are owner-only on Unix and removed when the operation finishes. Npack handles signer access, relay and storage configuration, and existing install trust decisions. The MCP server does not bypass interactive trust prompts: if npack needs user interaction, the operation fails because its stdin is closed.

The publisher identity and the MCP caller are both trusted to publish under the configured account. Keep this feature disabled for untrusted clients. Package tools are available over stdio or HTTP, so HTTP deployments must enforce their own client authentication and authorization policy.

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

The server supports authoring, dry simulation, sandboxed WASM execution, and explicitly opted-in live deploy sessions. Live sessions use NScript's compiler permission checks and configured host policies; they do not use WASI or the emitted `compile --emit wasm` artifact.
