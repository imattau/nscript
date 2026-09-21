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
- Added NIP-32 typed `Label` records and `publish_label`, with explicit
  namespace/value semantics for moderation and classification workflows.
- Added NIP-37 typed `Draft` records and `save_draft`, with explicit storage,
  signing, and relay effects for publishing workflows.
- Added NIP-38 typed `UserStatus` records and `publish_status`, with validated
  presence/activity fields and source/runtime conformance coverage.
- Added NIP-42 authenticated relay sessions as a runtime capability, with
  explicit relay/signing permission, URL validation, and typed session output.
- Added NIP-45 event counts as a relay effect, returning a typed integer for a
  validated filter without materializing matching events.
- Added NIP-50 typed `SearchRequest`/`SearchResults` and `search_events`, with
  explicit relay capability and query validation.
- Added NIP-53 typed `LiveEvent` records and `publish_live_event`, with
  addressable event validation and source/runtime conformance coverage.
- Added NIP-56 typed `Report` records and `publish_report`, with explicit
  moderation categories, rationale, and target validation.
- Added NIP-58 typed `Badge` records and `publish_badge`, with validated
  credential identifiers and descriptive metadata.
- Added NIP-68 typed `ImageEvent` records and `publish_image`, with explicit
  media URL/caption validation and source/runtime conformance coverage.
- Added NIP-71 typed `VideoEvent` records and `publish_video`, with explicit
  media URL/caption validation and source/runtime conformance coverage.
- Added NIP-77 Negentropy synchronization as a typed runtime primitive with
  explicit relay/storage effects, secure relay validation, and deterministic
  sync results.
- Added NIP-84 typed `Highlight` records and `publish_highlight`, with source
  and content validation for reading/annotation workflows.
- Added NIP-85 typed `Assertion` records and `publish_assertion`, with explicit
  subject/kind/value validation for trust and reputation workflows.
- Added NIP-86 typed `RelayAdminRequest` and `manage_relay`, with secure relay
  validation and explicit relay-admin capability enforcement.
- Added NIP-89 typed `AppHandler` records and `publish_handler`, with explicit
  event-kind/application/endpoint routing validation.
- Added NIP-94 typed `FileMetadata` records and `publish_file_metadata`, with
  URL, MIME, and content-hash validation for media/file workflows.
- Added NIP-B7 typed `BlobUpload`/`BlobStored` values and `upload_blob`, with
  explicit storage/HTTP effects and content-addressed upload validation.
- Added NIP-98 typed HTTP authentication requests/results, with secure URL and
  method validation behind explicit signing/HTTP capabilities.
- Added NIP-47 typed `WalletPayment`/`PaymentResult` values and `pay_invoice`,
  with positive-amount validation and an explicit `Payment` capability.
- Added policy-level payment budgets via `allow_payment_up_to`, enforcing the
  limit before a wallet host is invoked and returning a typed runtime error.
- Added typed NIP-46 signer-session provisioning through the operation host,
  preserving remote signer isolation and avoiding secret-key exposure.
- Added a dedicated `SignerProvisionHost` adapter and audited
  `Runtime::provision_signer` entry point for real remote-signer integrations.
- Added a dedicated `RelaySessionHost` adapter and audited
  `Runtime::authenticate_relay` entry point for authenticated relay sessions.
- Added an allowlisted `HttpHost` adapter and audited `Runtime::execute_http`
  entry point for controlled NIP-98 web bridging.
- Added transactional storage execution: `TransactionalStorageHost` commits
  staged writes only after a successful closure, rolls failed work back, and
  records committed/rolled-back outcomes in the runtime audit stream.
- Added a host-controlled `TimerHost` and audited `Runtime::schedule_timer`
  entry point for deterministic `every`/`at` scheduling with interval and
  catch-up metadata.
- Added checked schedule descriptors and `Runtime::schedule_program`, lowering
  literal `every` durations and `at` timestamps from source into host timers.
- Added atomic idempotency claims through `IdempotencyHost` and
  `Runtime::claim_once`, with duplicate-delivery outcomes recorded in audit.
- Added typed `SubscriptionHost` support and audited `Runtime::subscribe` for
  relay-backed stream filters with deterministic fake-host coverage.
- Added audited subscription cancellation through `Runtime::unsubscribe`,
  completing host-owned stream lifecycle management.
- Added typed `SubscriptionBatch` polling with completeness metadata through
  `Runtime::poll_subscription`, covering the relay stream delivery boundary.
- Added runtime event-ID deduplication during subscription polling, preventing
  relay retries from invoking handlers twice for the same signed event.
- Added explicit optional relay-set targeting to `SubscriptionRequest`, with
  host validation before stream creation.
- Added typed kind and tag-equality predicates to subscription filters, with
  validation before relay dispatch.
- Added a configurable subscription batch resource limit, rejecting oversized
  relay deliveries before they reach script handlers.
- Added `Runtime::poll_and_claim`, composing bounded polling with atomic
  idempotency claims before event handler delivery.
- Added typed subscription cursors on requests and batches for resumable relay
  streams after reconnects.
- Added bounded structured logging through `LogHost` and audited
  `Runtime::log`, keeping console output capability-scoped.
- Added committed-value snapshots to storage transactions, allowing reads of
  prior state while preserving staged-write rollback semantics.

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

## Draft 0.1 hardening and feature freeze

Draft 0.1 is now feature-frozen at the current NIP surface. New NIPs are
deferred unless required to complete an existing feature. The next milestones
are execution quality rather than protocol breadth:

1. Drive the conformance matrix to zero remaining release-blocker cells.
2. Execute `on`/`stream` handlers end to end with typed matching, idempotency,
   transactional storage, timers, and effects.
3. Add minimal real relay, NIP-46 signer, and SQLite storage hosts.
4. Expose inspectable permission manifests and dry-run execution.
5. Formalize signed package manifests and dependency locking. (Lockfiles and
   npack-compatible metadata are implemented; signing/distribution remain.)
6. Add WASM only after runtime semantics and real-host behavior stabilize.
   (Reference emission and Wasmi execution are implemented; production hosts
   remain.)

The `nscript inspect [--json]` command is the first security-UX slice: it
reports the checked profile, inferred effects, operation capabilities,
publication count, and schedule count without executing external effects.
`nscript run --dry-run` now exposes the same checked execution plan while
explicitly suppressing all external host effects.
The `--json` variant provides the same dry-run manifest for CI and agent
review tooling.
Normal `run` now registers checked timers through the same runtime scheduler
and reports their assigned handles before executing operations/publications.
It also lowers checked handlers into and reports typed subscriptions before
executing external operations.
Inspect output also lists checked handler event types and lowered author/tag
predicates for pre-execution review.
Checked handlers retain their typed AST body, and the first interpreter slice
executes direct `print("…")` statements through the bounded, audited
`LogHost`. Boolean `if`/`else` branches now execute recursively, including
short-circuit boolean operators and literal equality; broader expressions and
event-bound values remain next. The event-aware execution entry point now binds
`event.id`, `event.author`, and `event.content` for equality and substring
conditions, allowing delivered events to drive handler branches.
`run_handler_cycle_with_event_body` now connects that interpreter to the full
subscription → match → idempotency claim → transaction → unsubscribe path.
Handler `print` expressions can now render delivered `event.content`,
`event.author`, and `event.id` values as well as literals.
Numeric `event.kind` equality and inequality are also available to handler
conditions.
Typed tag predicates now support `event.tags.<name> contains "value"`,
preserving the protocol's tag structure while keeping handler code declarative.
`for tag in event.tags` now binds each tag as a stable `name=value` text value
for use in handler expressions, while keeping iteration bounded by the
delivered event.
Handler bodies can now bind event-derived text with local `let` declarations
and reuse those bindings in subsequent effects.
Handler `return` statements now stop the current body, including nested `if`
and `for` blocks, without being treated as unsupported syntax.
Value-bearing returns are rejected explicitly until handler result values become
part of the runtime effect model.
Runtime dispatch now also performs deterministic type/kind/author matching on
delivered signed events before body execution.
Signed-event values now carry typed `(tag, value)` pairs, allowing lowered tag
predicates to participate in local dispatch matching.
`UnsignedEvent::wire_tags` provides deterministic lowering back to ordinary
Nostr tag arrays for protocol serialization.
Subscription dispatch also enforces `since` timestamps locally before a
handler body is invoked.
`Runtime::dispatch_event` now claims a matching event atomically and invokes a
host-controlled body callback exactly once, auditing handler success/failure.
`Runtime::dispatch_event_transactional` composes that boundary with staged
storage, committing handler state only on successful body completion.
`Runtime::run_handler_cycle` now composes the full one-cycle transport path:
handler lowering, subscribe, poll, dispatch, transaction, and unsubscribe.
The conformance test exercises a queued signed event through that full path and
verifies committed handler state.
Handler-cycle polling and body failures now explicitly unsubscribe before
returning, preventing leaked relay subscriptions on error paths.
Added `RealRelayHost`, a NIP-01 WebSocket adapter for `ws://` relays with
typed filter lowering, `REQ`/`EVENT`/`EOSE`/`CLOSE` handling, signed-event
decoding, and publication `OK` outcomes. The deterministic fake host remains
the conformance backend. `RealRelayHost::reconnect` provides an explicit
session reset boundary; `reconnect_with_backoff` supplies bounded exponential
retry policy for callers that want recovery before rebuilding subscriptions.
The adapter now enables native-root Rustls support for `wss://` relay URLs.
`RealRelayPool` now reuses one WebSocket per relay, routes globally unique
subscription handles to their owning connection, fans out publications, and
supports reconnect-all recovery.
Release-blocker conformance now includes NIP-19 encode/decode round trips,
timer overlap rejection, and missing/incompatible package resolution tests.
Added `nscript package manifest`, which validates an NScript source program and
emits an `npack`-compatible manifest with runtime capability requirements and
an NScript permission/effect review section.
Added `nscript package lock`, which emits a deterministic lockfile containing
resolved module versions, canonical descriptor hashes, and transitive module
requirements for reproducible package builds.
Added `nscript package verify`, which rejects source/module-graph drift against
a committed lockfile before packaging.
`package manifest --lock` now verifies that lockfile and embeds its SHA-256
fingerprint in the generated package metadata.
Package manifests now also carry the script's resolved root module requirements
in the npack dependency field.
Manifests also expose the complete resolved module set with canonical hashes in
their NScript metadata.
`package manifest --hash-artifact` can compute the local archive digest directly
for npack handoff.
`package manifest --canonical` emits compact deterministic JSON as stable input
for future package signatures.
Documented the versioned `nscript-ir/0.1` interchange contract shared by JSON
IR output and the WASM custom sections.
Added `examples/layer3-bot.ns` as a runnable Layer 3 showcase combining native
publication syntax, typed event predicates, local bindings, conditions, logs,
and early returns.
Documented the Layer 3 lowering contract and queued `send`, `reply`, `repost`,
and `search` as syntax sugar over existing typed NIP modules.
Implemented `send "..." to recipient` lowering to `nip17.send_private` with
the existing typed permission and operation checks.
Implemented `reply "..." to target` lowering to `nip10.publish_reply`, with
the target used as both root and reply reference for the shorthand form.
Implemented `repost target` lowering to `nip18.publish_repost`.
Implemented `search EventType for "query"` lowering to
`nip50.search_events(SearchRequest { query })`.
Implemented `react "content" to target` lowering to
`nip25.publish_reaction`.
Implemented `zap recipient amount value` lowering to
`nip57.create_zap_request`; payment execution remains an explicit host effect.
Implemented `delete target` lowering to `nip09.request_deletion` with an empty
reason, preserving NIP-09's request semantics and deletion permission check.
Implemented `comment "content" on target` lowering to
`nip22.publish_comment` for arbitrary event targets.
Implemented `report target as category` lowering to `nip56.publish_report`
with an empty optional report description.
Implemented `label target as value` lowering to `nip32.publish_label` in the
default `nscript` namespace.
Implemented `status value` lowering to `nip38.publish_status` with an empty
optional status description.
Implemented `draft identifier with content` lowering to `nip37.save_draft`.
Implemented `badge identifier as name` lowering to `nip58.publish_badge` with
an empty optional description.
Implemented `highlight content from source` lowering to
`nip84.publish_highlight`.
Implemented `assert subject as kind value value` lowering to
`nip85.publish_assertion`.
Implemented `calendar title from start to end at location` lowering to
`nip52.publish_calendar_event`.
Implemented `live identifier titled title about summary` lowering to
`nip53.publish_live_event`.
Implemented `image url caption text` lowering to `nip68.publish_image`.
Implemented `video url caption text` lowering to `nip71.publish_video`.
Implemented `file url mime type hash digest` lowering to
`nip94.publish_file_metadata`.
Implemented `upload url hash digest size bytes` lowering to
`nipb7.upload_blob`.
Implemented `handler kind for app at endpoint` lowering to
`nip89.publish_handler`.
Added a durable `FileStorage` host for local deployments. It preserves the
existing transactional and idempotency interfaces using deterministic
tab-separated records and atomic replacement, providing a real persistent
backend without expanding the Draft 0.1 dependency surface.
Added the NIP-46 signer boundary: `Nip46SignerHost` validates bunker and
nostrconnect providers, binds signing to provisioned sessions, and delegates
transport/encryption to an injected `Nip46Transport` without exposing keys.
Started the WASM backend with deterministic `nscript-ir` artifacts: valid WASM
containers declare capability imports and carry the checked IR and capability
manifest in custom sections. `nscript compile --emit wasm` now emits the
artifact. The artifact now exports `nscript_main` and deterministically invokes
declared capability imports. A `nscript.dispatch` custom section carries the
serialized typed operation trace, and each lowered operation is now exposed as
a deterministic `op:<index>:<name>` host import invoked by `nscript_main`.
Operation imports now expose a first typed ABI as `(ptr, len)` pairs, with the
dispatch metadata remaining the authoritative payload until linear-memory
encoding is added. The dispatch JSON is now embedded in a one-page linear
memory data segment at offset zero, and `nscript_main` passes its actual length
to operation imports.
The runtime now provides bounded `decode_wasm_dispatch`, validating pointer/
length slices and JSON array shape before host-side operation mapping.
`WasmDispatchHost` and `dispatch_wasm_operations` now provide the invocation-
tracked host execution boundary for those decoded records.
`execute_wasm_publications` maps the create/sign/publish operation sequence to
the existing relay and signer hosts, preserving result handles and typed event
boundaries.
The CLI conformance suite now compiles a real `hello-note.ns` source artifact
and verifies the embedded dispatch markers for create, sign, and publish.
`execute_nscript_wasm` provides the deterministic reference executor: it
validates the WASM header, extracts `nscript.dispatch`, decodes it, and routes
the publication sequence through the signer and relay hosts.
`nscript compile --emit wasm --output <file>` now writes a packageable artifact
directly, completing the handoff into the existing npack manifest workflow.
Reference WASM dispatch is bounded to 1 MiB of payload and 1,024 operation
records, returning explicit resource-limit errors before host work begins.
Engine decision: Wasmi is the planned primary backend for Draft 0.1 because
its lightweight deterministic interpreter and built-in fuel metering fit the
capability sandbox; Wasmtime remains an optional performance backend. See
`docs/WASM-ENGINE.md`.
The runtime now declares Wasmi behind the opt-in `wasm-engine` feature; the
default build remains engine-free while the dependency is locked for
reproducible integration work.
The feature now exposes `wasmi_engine::WasmiEngine`, enabling fuel metering
and bounded module validation before host import binding. Its
`run_with_imports` path instantiates `nscript_main` with explicitly declared
zero-argument capability imports or `(i32, i32)` payload imports.
WASM artifacts now export their linear memory, allowing Wasmi `Caller`
callbacks to read the pointer/length dispatch payload directly.
`run_with_dispatch_host` now binds payload imports to `WasmDispatchHost`,
decoding memory slices and dispatching each indexed operation import exactly
once before returning the host state after `nscript_main` completes.
The CLI now has a feature-backed end-to-end test that compiles `hello-note.ns`,
executes it through Wasmi, and observes all three operation callbacks.
The same integration test verifies that a zero-fuel Wasmi budget rejects the
artifact before execution completes.
Wasmi stores now also apply a fixed 16 MiB linear-memory ceiling and bounded
instance/table counts for each execution.
Hosts can override those limits through `WasmiEngine::with_limits` while the
default constructor retains the safe bounded policy.
Payload imports are preflight-validated as unique `op:<index>:<name>` bindings
before Wasmi instantiation.
The CLI integration suite covers malformed payload import rejection.
Dispatch import indices and operation names are checked against the embedded
dispatch records before host callbacks can run.
The current Draft 0.1 blocker tranche is complete: `nscript inspect --json`
emits deterministic publication expansion and filter-lowering traces, the
hardened-agent profile rejects forbidden effects exposed transitively by
imported module operations, and replaceable-event selection now uses the
NIP-01 timestamp/lowest-id tie-break rule.

## Next strategic tranche: Concord protocol extensibility

Concord is the next major protocol target, with Armada serving as an
interoperability/testing client rather than a core language module. The full
rationale, protocol mapping, runtime requirements, examples, and staged CORD
roadmap are preserved in [`docs/CONCORD.md`](docs/CONCORD.md).

This tranche intentionally pauses broad NIP-sugar expansion and makes NScript
a typed execution environment for external Nostr protocols. The planned order
is: immutable `SignedBytes` plus `SharedSecret`/`DerivedKey`; capability-gated
ECDH/HKDF; CORD-01 private streams; deterministic state folds; CORD-02/03
community and channel models; CORD-04 authority and roles with a constrained
moderation bot; Armada interoperability; then CORD-05/06 key-management,
CORD-07 host/service integration, and CORD-08 disappearing-message timers.

Started the tranche with the `concord01` standard module descriptor. It defines
nominal `SharedSecret`, `DerivedKey`, and immutable `SignedBytes` boundaries,
the typed `StreamMessage` shape, and capability/permission-gated derivation
and publication operation contracts. Host implementations and CORD-01 wire
processing remain the next steps.
The runtime now also exposes non-empty, debug-redacted opaque wrappers for
these three byte classes, preventing accidental key-material disclosure in
ordinary debug output.
Added the `ConcordKeyHost` capability boundary and deterministic
`FakeConcordKeyHost` test double; production ECDH/HKDF remains intentionally
behind this host contract.
The fake operation host now preserves typed `SharedSecret`, `DerivedKey`, and
`StreamMessage` boundaries for `concord01.derive_stream_key` and
`concord01.publish_message`, providing the first executable CORD-01 path.
Added the `SealedEvent` boundary and deterministic seal/open operation
contracts; the fake host round-trip proves exact `SignedBytes` preservation
without exposing or reserialising the payload.
Added kind-1059 `StreamWrap` wrap/unwrap operations with stream-pubkey
validation, completing the CORD-01 wire path against the fake host; the
deterministic state-fold primitive is the next stage.
Added the generic `fold::Fold` reducer primitive: events are ordered by
`(created_at, id)`, deduplicated, capacity-bounded, and replayed from the
initial state so arrival order never changes the result. CORD-02/03 community
and channel models build on it next.
Added the `concord02` module descriptor (nominal `CommunityId`, `ChannelId`,
`Epoch`, `Channel`). Community state is now read from CORD-04 versioned
editions: `edition::EditionFold` implements the spec hash chain, refuse-
downgrade, authority-then-lowest-id tie-break, and tracking vs fresh-joiner
gap handling; `community::CommunityView` interprets community and channel
metadata (terminal deletion, 64-byte name cap, ignore-invalid-content).
CORD-01 rework landed: `stream` vocabulary (seal kinds 20013/20014 fixed per
plane, `group_key` labels, channel/epoch binding check), `SealedEvent` carrying
its kind, `StreamWrap` with ephemeral `p` and envelope validation, a
`derive_group_key` host method, and a verbatim plaintext Control seal.
Spec research (`docs/cord/FINDINGS.md`, specs vendored in `docs/cord/`) shows
the CORD-01 seal kinds and the CORD-02 community model need rework before
CORD-04: state is versioned editions, not ad-hoc events.

## Deferred

Module operation dispatch, full handler/stream evaluation,
cryptographic signing, NIP-44/NIP-59/NIP-46 host implementations, signed
package distribution, and a stable IR interchange format remain later phases.
