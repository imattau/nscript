# nscript-mcp

Install the NScript MCP server with `npx -y nscript-mcp@0.3.7` or add it as a project
dependency. The package exposes both `nscript-mcp` and the `nscript` CLI, and includes
the MCP server and WASM execution guest
for Linux x86_64/arm64, macOS Apple Silicon, and Windows x64/arm64.

Run CLI commands without a separate install with:

```sh
npx --yes --package=nscript-mcp@0.3.7 nscript deploy --help
```

The default transport is stdio. Add --http to run the opt-in Streamable HTTP
transport. HTTP mode requires NSCRIPT_MCP_BEARER_TOKEN; configure
NSCRIPT_MCP_ALLOWED_ORIGINS and, when serving a non-local hostname,
NSCRIPT_MCP_ALLOWED_HOSTS.

WASM sandbox execution is dry by default. Live relay execution and durable
bot sessions are disabled until the server administrator sets
NSCRIPT_MCP_LIVE_ENABLED and configures NSCRIPT_MCP_RELAYS, NSCRIPT_MCP_SIGNERS,
NSCRIPT_MCP_INPUTS, and NSCRIPT_MCP_STATE_DIR. Durable sessions can refer to
server-held input values without storing them in session records. See the
repository MCP guide for the full policy and host configuration.
