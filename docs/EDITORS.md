# Editor support

`nscript-lsp` is a Language Server Protocol server for NScript. It adds no
analysis of its own: diagnostics, completions, hover and the outline come from
`nscript-lang`, which runs the same parse, module resolution and semantic
analysis as `nscript check`, and the authority summary comes from the same
`footprint` function Studio's permission panel uses. A test runs
`nscript check` and the server over every source in `conformance/`, `examples/`
and `templates/` and requires identical diagnostics (code, message and
position), so the editor cannot quietly disagree with the CLI.

## What it provides

| Feature | LSP method |
| --- | --- |
| Diagnostics, updated as you type | `textDocument/publishDiagnostics` |
| Completions (`use` lines, `module.`, `event.`, keywords, locals) | `textDocument/completion` |
| Hover | `textDocument/hover` |
| Outline | `textDocument/documentSymbol` |
| Authority summary | `textDocument/codeLens` and `nscript/authority` |

The **authority summary** is a lens on the first line of the file, for example
`Authority: Nostr: Connect to relays, Handle ServiceState | System: Structured logging`
(the read-only relay monitor template; a bot that publishes would also list
`Publish Note to public` and `Sign Note`). Anything the program uses but
has not declared under `permissions` is marked `(not declared)`, and it is
shown while you type, before `check` would reject the file. Selecting the lens
runs `nscript.showAuthority`, which the VS Code extension shows in full. A
client that wants the data itself can send `nscript/authority` with a
`textDocument` and receives `{ "groups": [...] }`.

## Limits

- Only the built-in standard library resolves. Module directories passed to the
  CLI with `-M` are not loaded.
  The four examples that import external modules (`moderation.ns`,
  `server-monitor.ns`, `constrained-agent.ns`, `http-integration.ns`) therefore
  show a missing-module error in an editor even though `nscript check -M
  examples/modules` accepts them.
- No go-to-definition, rename, references, formatting or code actions.
- Single-file analysis, full-document sync.
- Positions use UTF-16 code units, as the protocol requires.

## Build the server

```bash
cargo build --release -p nscript-lsp
# target/release/nscript-lsp
```

It speaks LSP over stdin/stdout. Put the binary on your `PATH` or point your
editor at it.

## VS Code

The extension in `editors/vscode` is a thin client over the server. It is not
published to a marketplace; run it from a checkout:

```bash
cd editors/vscode
npm install
code --extensionDevelopmentPath "$PWD"
```

Set `nscript.server.path` if `nscript-lsp` is not on your `PATH`.

## Other editors

Any LSP client works with `nscript-lsp` as the command, stdio transport, for
files ending in `.ns`.

Neovim (0.8 or later), in `init.lua`:

```lua
vim.filetype.add({ extension = { ns = "nscript" } })
vim.api.nvim_create_autocmd("FileType", {
  pattern = "nscript",
  callback = function()
    vim.lsp.start({
      name = "nscript",
      cmd = { "nscript-lsp" },
      root_dir = vim.fn.getcwd(),
    })
  end,
})
```

Zed and other editors that load language servers only through their own
extension mechanism need an extension, which this repository does not ship.

## What has and has not been verified

Verified by automated tests: the protocol handler (lifecycle, diagnostics,
completion, hover, outline, lens, error handling, UTF-16 positions), a real
stdio session against the built binary including framing and exit codes, parity
with `nscript check` over the whole corpus, that the VS Code grammar covers the
language's statement keywords, and the extension's own logic with the editor
stubbed.

**Not verified:** running the extension inside a real VS Code, or the Neovim
snippet inside a real Neovim. Nobody has done either yet, so treat those two
setups as unconfirmed until someone has.
