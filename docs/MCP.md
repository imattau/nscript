# MCP server

`nscript-mcp` exposes NScript's existing check, inspection, and simulator
workflows to MCP-compatible agents. It is general-purpose: it knows NScript,
not any particular social network or Nostr application.

## Build

Build the server and CLI from the repository root:

```sh
cargo build --release -p nscript-mcp -p nscript-cli
```

The server runs over stdio. It finds `nscript` beside its own executable; set
`NSCRIPT_CLI_PATH` when the CLI is installed elsewhere or has a different name.
Both executables must remain available to the same user account. The server
does not write logs to stdout because stdout carries MCP messages.

Example MCP client configuration:

```json
{
  "mcpServers": {
    "nscript": {
      "command": "/path/to/nscript-mcp",
      "env": {
        "NSCRIPT_CLI_PATH": "/path/to/nscript"
      }
    }
  }
}
```

## Tools

- **`nscript_check`** accepts source and returns compiler diagnostics with a
  success or failure status. Optional `module_dirs` supplies custom module
  directories, passed to the CLI with `-M`.
- **`nscript_inspect`** accepts source and returns the structured manifest,
  including effects, resolved modules, operation calls, and publication trace.
  Optional `module_dirs` supplies custom module directories.
- **`nscript_simulate_event`** accepts source and a JSON event, then delivers
  that event to matching handlers using `nscript run`'s simulator. Optional
  `principal` supplies the program's `me` value (`--as`); `inputs` supplies
  declared `Text`, `Integer`/`Int`, `Bool`, or `PubKey` inputs as JSON strings,
  integers, or booleans. Optional `module_dirs` supplies custom module
  directories.

Simulation is explicitly dry: it does not connect to relays, publish events,
or access signer keys. Operations without a simulator implementation are
recorded and answered with declared placeholder values, as in the CLI. A tool
result reports CLI failures with MCP's `isError` field.

The server accepts source up to 1 MB and event JSON up to 256 KB. It creates a
temporary `.ns` file with owner-only permissions on Unix, removes it after the
CLI command, and redacts the temporary path from diagnostics. CLI execution
has a 30-second timeout. Custom module directories are explicit local paths
provided by the caller; the built-in module registry is always available.

## Scope

This server supports authoring and dry simulation. It does not expose `deploy`
or any live network, signing, filesystem, or package mutation tool. A future
live host should grant capabilities through NScript's normal permission and
host policies rather than turning the MCP server into an unrestricted relay
or signer proxy.
