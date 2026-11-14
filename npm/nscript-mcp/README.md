# nscript-mcp

Install the NScript MCP server with npx -y nscript-mcp@0.3.6 or add it as a project
dependency. The package includes the NScript CLI, MCP server, and WASM execution guest
for Linux x86_64/arm64, macOS Apple Silicon, and Windows x64/arm64.

The default transport is stdio. Add --http to run the opt-in Streamable HTTP
transport. HTTP mode requires NSCRIPT_MCP_BEARER_TOKEN; configure
NSCRIPT_MCP_ALLOWED_ORIGINS and, when serving a non-local hostname,
NSCRIPT_MCP_ALLOWED_HOSTS.
