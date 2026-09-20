# Next Phase: Complete Compiler Front End

## Summary

Replace the current structural scanner with a real parser and static-analysis
pipeline. This phase will parse complete `.ns` programs and declarative `.nsm`
modules, resolve local and built-in modules deterministically, and enforce
nominal types, event signing states, effects, permissions, queries, and
hardened-agent restrictions. Runtime execution remains out of scope.

## Compiler and module interfaces

- Introduce full, spanned ASTs for declarations, statements, expressions,
  patterns, types, permissions, defaults, and module schemas.
- Use a handwritten recursive-descent parser with error recovery. Add focused
  dependencies only for Unicode identifiers, semantic versions, and SHA-256.
- Define validated public structures including `ModuleId`, `ModuleDescriptor`,
  `TypeDefinition`, `EventDefinition`, `TagDefinition`, `HostOperation`,
  `EffectSet`, `Permission`, `TypedProgram`, and `FilterPlan`.
- Parse `.nsm` validation expressions through the restricted pure-expression
  grammar. Reject recursion, I/O, dynamic wire names, duplicate wire positions,
  unbounded operations, and invalid event modes with `E4003`.
- Add a versioned deterministic descriptor encoding and golden hash vectors.
  Declaration order, whitespace, comments, and module-path ordering must not
  affect hashes where semantics are unchanged.
- Ship declarative built-ins for NIP-01, NIP-10, NIP-19, and NIP-46 through the
  same parser and validator as third-party modules.

## Resolution and static semantics

- Resolve imports from embedded built-ins plus repeatable `--module-path`
  directories; checking never performs network access.
- Select the highest version satisfying the complete dependency graph. Reject
  cycles, unsatisfied ranges, and different descriptors claiming the same
  name/version. Module-path order never resolves conflicts or shadows built-ins.
- Implement lexical scopes, qualified imports, duplicate-name detection, and
  separate namespaces for types and values.
- Type-check primitives, containers, nominal Nostr types, records, enums,
  functions, event constructors, typed tags, `Option`, and `Result`.
- Model construction as `Unsigned<E>`, signing as `Signed<E>`, and publication
  as accepting signed events or expanding a source-declared signer default.
- Expand publication defaults into typed IR before effect and permission
  checking; defaults never create authority.
- Infer effects to a fixed point across calls, recursion, and imported host
  operations, then compare reachable effects with structural permissions.
- Apply hardened-agent restrictions transitively to source, imported types,
  module initialization requirements, effects, permissions, and defaults.
- Type-check matches for exhaustiveness and unreachable arms.
- Lower supported queries into typed `FilterPlan` values, requiring bounded
  relay supersets for local predicates.

## CLI and diagnostics

- Preserve `nscript check <file>` and add repeatable `--module-path <directory>`
  plus `--format human|json`.
- Add `nscript module check <file.nsm>` and `nscript module hash <file.nsm>`.
- Retain exit codes `0` for success, `1` for diagnostics, and `2` for usage or
  filesystem failure.
- Emit stable codes, primary and secondary spans, notes, and normalized JSON.
- Keep existing `E2203`, `E2204`, and `E5001` behavior while replacing lexical
  policy scans with typed semantic checks.

## Test and acceptance plan

- Cover Unicode XID identifiers, escapes, comments, numeric forms, newline
  suppression, and malformed input in lexer tests.
- Add positive and recovery-oriented parser fixtures for every `.ns` and `.nsm`
  production.
- Test canonical hashes, equivalent descriptors, conflicts, cycles, version
  selection, validators, tag positions, and built-in/third-party parity.
- Run every conformance fixture through `nscript check`, verifying its declared
  outcome and diagnostic span.
- Cover nominal types, signing states, tags, matches, effects, permissions,
  hardened transitive denial, defaults, and query bounds.
- Require formatting, strict Clippy, unit tests, conformance tests, hash vectors,
  and specification checks in CI.

## Assumptions

- Internal Rust APIs may break; the documented CLI and diagnostic codes remain
  stable.
- Module resolution is local and deterministic; Nostr/Blossom fetching remains
  deferred.
- No interpreter, relay connection, cryptography, signer or storage backend, or
  WASM execution is included.
- `semver` 1.x, `sha2` 0.10.x, and `unicode-ident` 1.x are approved; `Cargo.lock`
  pins selected releases.
