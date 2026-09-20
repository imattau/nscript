# Conformance corpus

Fixtures are source-level contracts for compiler and runtime implementations.

- `valid/` programs must parse and type-check.
- `invalid/` programs must fail with the diagnostic code named in the leading
  `// error:` comment.
- `scenarios/` describes host-driven runtime tests that require relay, signer,
  store, or clock fakes.

The first Rust interpreter should expose a test runner that walks this tree and
compares normalized diagnostics and host traces. Fixture comments are metadata,
not language directives.
