# NScript for VS Code

Diagnostics, completions, hover, an outline and a live authority summary for
`.ns` files, from the same front end as the `nscript` CLI. This extension is a
thin client: all analysis is in `nscript-lsp`. See
[`docs/EDITORS.md`](../../docs/EDITORS.md) for what it provides, its limits, and
what has been verified.

```bash
cargo build --release -p nscript-lsp   # then put target/release on your PATH
npm install
code --extensionDevelopmentPath "$PWD"
```

Settings: `nscript.server.path` (default `nscript-lsp`).

`npm test` runs the extension's logic tests under plain Node with the editor
stubbed. They do not start VS Code.
