# Next Phase: Typed Front End and Publish IR

## Summary

Replace the structural source scanner with a complete Draft 0.1 parser and type
checker. Every current `.ns` conformance fixture will be genuinely checked.
Publication programs will additionally lower to deterministic Nostr IR, without
performing relay, signer, storage, or other host effects.

## Compiler front end

- Build a fully spanned AST for declarations, statements, expressions, types,
  patterns, queries, handlers, stores, timers, signing, and publication.
- Add source-aware structured diagnostics with severity, primary and secondary
  labels, notes, recovery, and mandatory secret redaction.
- Resolve lexical names, core types, and module exports; reject ambiguity,
  incompatible versions, invalid references, and duplicate declarations.
- Type-check primitives, containers, nominal values, records, events,
  `Unsigned<E>`, `Signed<E>`, capabilities, results, functions, and patterns.
- Infer transitive effects and structurally match them against permissions.

## Modules and IR

- Add pure callable signatures to declarative modules alongside host operations.
- Put `Note` and the open `Tag` interface in NIP-01; keep NIP-10 responsible for
  reply/root tag constructors; expose NIP-19 conversions, NIP-46 provisioning,
  and the high-risk `keys` capability declaratively.
- Introduce `CheckedProgram` and deterministic `nscript-ir/0.1` JSON containing
  resolved modules, capabilities, permissions, and publication operations.
- Add `nscript compile --emit ir [-M <root>] <file>`; keep `nscript check` as
  the validation-only command.

## Acceptance

- Every source in `conformance/valid` parses and type-checks.
- Every source in `conformance/invalid` reports its declared diagnostic code.
- Golden IR proves `CreateEvent -> SignEvent -> PublishEvent`, including
  default expansion and exact module versions and hashes.
- Module, resolver, parser, type, effect, permission, redaction, specification,
  Clippy, and workspace tests pass locally and in GitHub Actions.

## Completed in this phase

- Added the `nscript-runtime` crate with typed relay, signer, clock, audit, and
  storage host contracts.
- Added deterministic fake relay/signer/clock/audit/storage hosts and runtime
  tests for signer denial, partial publication, audit ordering, and rollback.
- Added `nscript run <file>` for checked publication execution against fake hosts.
- Added declarative NIP-44, NIP-59, and NIP-17 modules with typed encrypted
  payloads, gift wraps, private messages, and explicit encryption/signing/relay
  effects; NIP-17 resolves its NIP-44 and NIP-59 dependency graph.
- Added typed runtime operation dispatch with an explicit `OperationPolicy`, so
  undeclared module operations are denied before reaching a host capability.
- Added module-call validation: qualified and unqualified imported exports are
  checked for ambiguity, argument arity, and declared operation permissions.
- Carried checked module calls into `CheckedProgram` and added runtime execution
  through the authorized operation host boundary.
- Wired `nscript run` to execute checked module calls and added a NIP-44 source
  conformance fixture proving the CLI path.
- Added a NIP-17 source fixture with typed `PrivateMessage` construction and a
  fake relay publication report from the composed operation host.
- Added a pure-function host boundary with real NIP-19 `npub` Bech32 checksum
  validation and conversion to nominal `PubKey`, including invalid-input tests.
- Extended NIP-19 with nominal `Nprofile`, `Nevent`, and `Naddr` values and
  checksum-validated constructors.
- Added the typed NIP-65 `RelayList` schema and an authorized relay-list
  publication host operation with deterministic outcome coverage.
- Added typed NIP-78 `AppData` with explicit addressable application-data
  publication and deterministic runtime coverage.
- Added typed NIP-02 `FollowList` publication with explicit follow-list
  capability effects and deterministic runtime coverage.
- Added typed NIP-25 `Reaction` publication referencing nominal `EventId`
  values with deterministic runtime coverage.
- Added typed NIP-09 `DeletionRequest` publication, explicitly modeling
  deletion as a relay request rather than a guaranteed erase.
- Added typed NIP-51 `UserList` publication with nominal `PubKey` members and
  deterministic runtime coverage.

## Deferred

Module operation dispatch, full handler/stream evaluation, live relays,
cryptographic signing, NIP-44/NIP-59/NIP-46 host implementations, WASM,
package distribution, and a stable IR interchange format remain later phases.
