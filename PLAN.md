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
- Added typed NIP-57 `ZapRequest` and `PaymentIntent`, enforcing positive
  amounts while keeping payment authorization outside request creation.
- Added typed NIP-52 `CalendarEvent` publication with timestamp ordering
  validation and deterministic runtime coverage.
- Added typed NIP-66 `RelayStatus` publication with uptime and latency bounds
  for relay monitoring automation.
- Added typed NIP-5A `SiteDeployment` publication with explicit storage,
  signing, and relay effects for NostrHost-oriented deployment workflows.
- Added a generic typed-record boundary for checked module arguments. Source
  constructors now lower recursively into runtime records, preserving nominal
  record names and field values across the capability boundary. Runtime hosts
  normalize scalar NIP records into their validated typed values before
  dispatch, while preserving legacy typed host calls.
- Added the first next-tranche module, NIP-10, with typed `Reply` records,
  root/target references, a `publish_reply` operation, reply-tag lowering, and
  valid source/runtime conformance coverage.
- Added NIP-18 typed `Repost` records and `publish_repost`, with validated event
  references, repost lowering, and source/runtime conformance coverage.
- Added NIP-22 typed `Comment` records and `publish_comment`, allowing comments
  to target arbitrary events with validated content and source/runtime coverage.
- Added NIP-23 typed `Article` records and `publish_article`, modeling
  addressable long-form content with validated identifiers and source/runtime
  coverage.
- Added NIP-29 typed `GroupMessage` records and `publish_group_message`, with
  explicit group scope, validation, and source/runtime conformance coverage.

## Next tranche: content, groups, relay tooling, payments, and extensibility

The next NIP tranche broadens NScript from basic social/event scripting into a
general Nostr application and automation language. Implementations MUST choose
NIPs by use case and protocol maturity rather than attempting to support every
published NIP.

### Language-facing features

These NIPs should become concise syntax where they express common intent:

- NIP-10: typed replies, roots, mentions, and thread structure (`reply to`).
- NIP-18: reposts (`repost note`).
- NIP-23: long-form articles, editing, and querying (`publish Article`).
- NIP-29: relay groups, membership, and group-scoped handlers.
- NIP-45: event counts (`count ... where ...`).
- NIP-50: search (`search Note for ...`).
- NIP-53: live events and spaces.
- NIP-68 and NIP-71: image-first and video events.

### Typed modules

These should expose structured records and operations without adding a keyword
for every protocol detail:

- NIP-22 comments and arbitrary comment targets.
- NIP-32 labels for moderation, classification, and trust signals.
- NIP-37 drafts and publishing workflows.
- NIP-38 user status and presence.
- NIP-47 Nostr Wallet Connect, with explicit payment effects and budgets.
- NIP-56 reporting.
- NIP-58 badges and credentials.
- NIP-84 highlights.
- NIP-85 trusted assertions.
- NIP-89 application handlers and routing.
- NIP-92, NIP-94, and NIP-B7 media metadata, files, and Blossom storage.
- NIP-C7 broader chat models complementing NIP-17.

### Runtime primitives

These should normally remain behind relay, storage, or transport capabilities:

- NIP-42 authenticated relay sessions.
- NIP-67 EOSE/completeness handling.
- NIP-77 Negentropy synchronization.
- NIP-86 compatible relay administration.
- Media upload/download transport and relay capability selection.
- NIP-98 HTTP authentication for controlled web/API bridging.

### Staged delivery

1. Add typed schemas and conformance fixtures for threads, reposts, comments,
   long-form content, search, counts, groups, and moderation labels.
2. Add explicit payment and wallet capabilities, then media/file modules and
   relay-management operations with auditable policy checks.
3. Add runtime synchronization, authenticated relay sessions, trusted
   assertions, application handlers, live-media support, and advanced wallet
   flows.

The acceptance bar for each addition is a typed module descriptor, capability
and effect declarations, invalid-input fixtures, deterministic fake-host tests,
and documented wire-level lowering to existing Nostr protocols.

## Deferred

Module operation dispatch, full handler/stream evaluation, live relays,
cryptographic signing, NIP-44/NIP-59/NIP-46 host implementations, WASM,
package distribution, and a stable IR interchange format remain later phases.
