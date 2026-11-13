# nscript-mcp

Install the NScript MCP server with npx -y nscript-mcp or add it as a project
dependency. The package includes the NScript CLI and MCP server for Linux
x86_64 and macOS Apple Silicon.

The default transport is stdio. Add --http to run the opt-in Streamable HTTP
transport. HTTP mode requires NSCRIPT_MCP_BEARER_TOKEN; configure
NSCRIPT_MCP_ALLOWED_ORIGINS and, when serving a non-local hostname,
NSCRIPT_MCP_ALLOWED_HOSTS.
