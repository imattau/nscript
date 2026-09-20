# Next Step: Complete Module Schema and Local Resolution

## Summary

Finish the declarative module subsystem before expanding source-language typing.
The compiler will parse every `.nsm` construct, build complete descriptors,
discover built-in and local modules, resolve version graphs deterministically,
and attach resolved imports to checked programs. Runtime execution and general
expression typing remain deferred.

## Module model and parsing

- Expand `ModuleDescriptor` with dependencies, nominal types, records, enums,
  validators, events, tags, host operations, errors, vectors, canonical encoding
  version, source identity, and hash.
- Add spanned AST nodes for restricted validation expressions, type references,
  parameters, effects, and permission templates.
- Parse every production in `module-schema.ebnf`, with recovery at declaration
  boundaries.
- Add named validators with an acyclic call graph. Reject recursion, unknown
  fields/functions, effects, I/O, unbounded collection operations, and
  unsupported calls with `E4003`.
- Validate unique exports, event-kind compatibility, addressable-event
  requirements, tag position continuity, optional-field placement, operation
  effects, and permission templates.
- Introduce `SourceId` and multi-source diagnostics with primary/secondary
  labels so import and conflict errors can reference multiple files.

## Canonical descriptors and resolution

- Introduce canonical descriptor encoding version 2 containing every public
  descriptor field and dependency. Update the golden vector; version 1 remains
  identifiable but is not used for new descriptors.
- Store built-ins as ordinary `.nsm` files for NIP-01, NIP-10, NIP-19, and
  NIP-46 and load them through the public parser.
- Discover local modules from repeatable `--module-path` roots using
  `<root>/<module segments>/<version>.nsm`. Canonicalized files must remain
  inside their configured root.
- Add `ModuleRegistry` and `ResolvedModuleGraph` APIs. Identical
  name/version/hash entries deduplicate; differing hashes for one identity
  produce `E4003`.
- Aggregate semantic-version constraints and select the highest compatible
  version. Reject missing versions with `E4002` and dependency cycles with
  `E4001`; module-path order never affects selection.
- Parse program `use` declarations into imports and resolve them before existing
  semantic checks. No network lookup or package installation occurs.

## CLI and tests

- Extend `nscript check` with repeatable `-M`/`--module-path` options.
- Add `nscript module describe <file.nsm>` with deterministic human output;
  retain `module check` and `module hash`.
- Test every module declaration form, malformed-input recovery, restricted
  validators, duplicate exports, tag errors, event constraints, and operations.
- Add resolution tests for built-ins, local modules, transitive dependencies,
  version selection, deduplication, conflicts, missing dependencies, cycles,
  path-order independence, and root escapes.
- Add golden version-2 hashes and prove comments, whitespace, and semantically
  irrelevant declaration ordering do not change them.
- Require all existing tests, strict Clippy, specification checks, module
  fixtures, and CLI integration tests to pass in CI.

## Assumptions

- Internal descriptor and diagnostic APIs may change.
- Existing diagnostic codes remain stable; multi-source labels are additive.
- Canonical version-1 hashes are draft artifacts and need not resolve as
  installable packages.
- Source type inference, event-state propagation, effect inference, and query
  lowering begin only after the resolved module graph is available.
