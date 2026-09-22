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
CORD-04 authority landed (`authority.rs`): frozen permission bits, owner proven
by `community_id`, Roles/Grants/Banlist folded to a fixed point starting at the
owner, strict-outrank checks, `vac` citations (present, synced, hash-matching,
resolved against the current roster), keyless `concord/grant` and
`concord/banlist` coordinates via RFC 5869 HKDF, and `Roster::can` for
capability-checked actions. Guestbook kicks, `control_wrap` delivery and pins
remain.
Added the `concord04` module and `moderation::ModerationHost`, the constrained
moderation bot boundary: the program's `OperationPolicy` decides which
operations a script may call (a kick-only bot cannot ban), and the host
separately enforces the CORD-04 bit plus strict-outrank rule against the live
Roster, so revocation takes effect on the next re-fold. Kick and ban currently
record directives; composing them into Grant/Banlist editions and the
Refounding is later host work.
Added `wire.rs`: kind-3308 rumor decoding into editions (tag encoding rules,
author-equals-seal check, verbatim content, NIP-01 rumor id), with the
concrete payloads from `docs/cord/examples.md` run through the parsers as
vectors. Live Armada interop is still untested.
Concord conformance now uses ordinary source programs (`module.operation(...)`
with record literals and a `permissions` block), including a negative fixture
showing a kick-only bot cannot call `ban_member` (E3001). The `stream` /
`on chat.message` / `concord Kick in devs` sugar from `docs/CONCORD.md` is not
implemented and would need a language RFC.
Added the CORD-02 §5 Guestbook fold (`guestbook.rs`): join/leave/kick/snapshot
rumor decoding (`ms` tag, dropped when out of range), per-npub coalescing by
`(time, lowest rumor id)`, the one-hour future limit, kicks gated by the KICK
bit, strict outrank and a synced `vac`, refounder-only snapshots that lose to
newer first-hand entries, and the Complete Memberlist with forward-only
observation and Banlist removal.
Added CORD-08 disappearing messages (`expiry.rs`): the `message_expiration`
metadata field (off when absent, zero or malformed), NIP-40 tag computation
with the delete, timer-notice and ephemeral exemptions, enforcement by the
signed rumor's own tag (refuse at ingest, hide, sweep), and timer notices
believed only from `MANAGE_METADATA` holders. Wiring the sweep to `TimerHost`
and tagging the outer wrap are host work.
Drafted [RFC 0002](rfcs/0002-concord-language-surface.md) proposing generic
module-provided stream sources, scoped permissions and fold queries so the
`docs/CONCORD.md` sugar can be expressed without Concord-specific compiler
support. It is a proposal only and awaits review.
Added CORD-06 receive-side logic (`rekey.rs`) on fakes: rekey tag and blob-list
parsing, fixed-width blob forms (72/104/136 bytes) with scope and epoch bound
inside the ciphertext, staff `control_root`-derives-to-`control_pk` check,
recipient locators, epoch-key continuity (extends / missed / fork), chunk
assembly where removal needs a complete set, lowest-key race winner with a
down-only heal, and rotator authority (BAN for a Refounding, MANAGE_CHANNELS
for a channel rekey, strict outrank, synced `vac`). NIP-44 blob decryption and
compaction publishing remain host work; CORD-05 invites are next.
Added CORD-05 invite logic (`invite.rs`): `CommunityInvite` validation (owner
self-certified against `community_id`, 256-channel bound, relay truncation,
expiry gating joins only, legacy `control_pk`), the base64url link fragment
codec with the relay dictionary, `bundle_key`, the mergeable Invite List with
terminal tombstones and preserved unknown fields, the Registry fold that
decides Public/Private and flags the Refounding on retiring the last link, and
Direct Invite (kind 3313) parsing with the `#k` index filter. The fragment
flag bit position is assumed (the spec names it, not its bit) and must be
confirmed against a reference implementation.
Started the separate `nscript-host-crypto` crate (RustCrypto: `k256`, `hkdf`,
`hmac`, `chacha20`, `base64`) so the core runtime stays dependency-light. It
holds real CORD-02 Appendix A `group_key` derivation (HKDF, `scalar_normalize`
retry, x-only keys, self-ECDH conversation key), NIP-44 v2, and a
`Nip44KeyHost` implementing `ConcordKeyHost`. NIP-44 passes every official
vector from `paulmillr/nip44` (conversation keys, message keys, padding,
encrypt/decrypt, 65,535-byte messages, invalid inputs); HKDF agrees with the
runtime's independent RFC 5869-tested implementation. There are no official
`group_key` vectors, so derivation is covered by properties and cross-checks
only. BIP-340 Schnorr signing and verification (`schnorr.rs`) passes all 19
official vectors (8 signing, 19 verification), and `random32`/`encrypt` use OS
randomness. Seal/wrap host operations and blob wrapping remain to be built on
it.
Live interop (2026-09-21, `nscript-host-crypto` examples `concord_fetch_invite`
and `concord_interop`) against a real Concord community created from an
invite link: the bundle was fetched from relays and decrypted with the
token-derived key (confirming `bundle_key`, the fragment codec and the assumed
bit-0 stock-relay flag on a real link), the owner self-certified against the
`community_id`, all 7 Control Plane wraps opened and verified (`concord/control`
`group_key`, NIP-44, BIP-340, plaintext seals) and folded through
`AuthorityFold` into the community metadata, channels and role, and the public
channel's chat was decrypted. A throwaway identity then joined the Guestbook
and posted kind 9, quote and kind 1111 messages with CORD-08 expiration tags on
rumor and wrap; all were accepted by the relays and read back and verified.
`stream.rs` provides the real wrap/seal builder and opener behind this. Not
yet confirmed: rendering in an Armada client. Found on the way: tungstenite's
`rustls-tls-native-roots` feature selects no crypto provider, so any `wss://`
connect panics until one is installed; the runtime's `RealRelayHost` has this
gap for production relays. Fixed: `RealRelayHost` now opens sockets through
`open_socket`, which installs the `ring` rustls provider when the host has not
installed one, verified by an opt-in real TLS handshake test.
The real `concord01` host operations landed in `nscript-host-crypto`
(`Nip44OperationHost`): `seal_message`, `seal_control_message`, `open_message`,
`wrap_stream` and `unwrap_stream` build and open real CORD-01 events, carrying
rumor bytes verbatim, keeping the author's key inside the host, and mirroring a
rumor's `expiration` onto the outer wrap (CORD-08). `StreamWrap` now carries an
optional `wire` event and an optional seal so a received wrap can be handed to a
host unopened. Run against the live community's channel, the operations opened
all 6 events with none refused. Limits: the Control Plane's split signer and
read key need two keys and are not yet expressible through one `DerivedKey`;
`publish_message` and `derive_stream_key` stay unavailable on the real host.
`publish_message` is now real on `Nip44OperationHost` (`with_publisher` +
`PublishTarget`): it builds a kind-9 rumor with the channel/epoch binding, `ms`
and CORD-08 expiration tags, seals and wraps it, and delivers through any
`RelayHost` (`RealRelayPool` in production). The message author must be the
host's own identity, so a script cannot publish as anyone else. Verified live:
a real `publish_message` call through `OperationPolicy` and `RealRelayPool` over
TLS reached three relays and read back. That exposed and fixed three
`RealRelayHost` defects: reads had no timeout (a silent relay hung the
program), `publish` took the next frame as its answer instead of the `OK` naming
its event, and `RealRelayPool::publish` aborted on the first failing relay
instead of reporting partial publication.
The `concord04` bot now acts for real (`ConcordModerationHost` in
`nscript-host-crypto`, plus `wire::build_edition` as the exact inverse of the
edition decoder). `ban_member` publishes a chained Banlist edition on the
Control Plane (plaintext seal by the actor, wrap by the `control_root` signer,
read key from the `community_root`), keeping earlier bans and citing the
actor's own Grant. `kick_member` performs Role Removal (only when the actor
holds MANAGE_ROLES and the staff key) and then a Guestbook kick, degrading to
the weaker removal otherwise, per CORD-04 §6. Both re-check the CORD-04 bit and
strict-outrank rule, so the runtime `OperationPolicy` and the roster remain two
independent gates. Proved on a self-made local community: an independent reader
holding only member-level keys opens every published wrap and folds it through
`AuthorityFold` and `Guestbook` (bans take effect, roles are stripped, kicks
land). Not run against the live community: the throwaway identity has no
authority there, so such editions would be dropped. A ban is the Banlist layer
only; the Refounding that severs read access is still unbuilt.
CORD-06 rekey delivery is built on both sides (`rekey.rs` in
`nscript-host-crypto`): `build_rekey_events` wraps 72/104/136-byte blobs under
the rotator-recipient pairwise NIP-44 key, locates them by public-key locator,
and publishes kind-3303 events at the address derived from the prior root;
`receive_rekey` opens them, checks continuity and caller-supplied authority,
decrypts its own blob and adopts it, concluding removal only from a complete
chunk set and picking the lowest base key among racing rotators. Tested in both
directions for members, staff, removed members, missing chunks, unauthorised
rotators, forks and channel rekeys. Spec note found while testing: 120 base
blobs per event do not fit the envelope. Each event is NIP-44 encrypted twice
and the wrap layer caps plaintext at 65,535 bytes; by NIP-44's padding rules 104-
and 136-byte blobs overflow that at roughly 110 and 100 blobs, so chunk size
shrinks until the rotation fits (72-byte channel blobs do fit 120). Worth
raising with the CORD authors. Still unbuilt: Control Plane compaction and the
whole-Refounding orchestration.
On 2026-09-21 the owner granted the throwaway interop key a moderator role;
read-only against the live Control Plane, `AuthorityFold` resolves it to rank 2,
permission bits 568 (KICK, BAN, MANAGE_MESSAGES, MENTION_EVERYONE) and staff,
matching the grant. No moderation action has been taken on the live community.
The Refounding is built (`refound.rs` in `nscript-host-crypto`):
`plan_refounding` authorizes the rotator (BAN, strict outrank of every removed
target, synced citation), archives-and-rewraps every current Control head
verbatim (plaintext seals keep the original authors' signatures; a head with
no archived seal aborts the whole Refounding rather than dropping authority),
rolls `community_root` and `control_root` through rekey blobs, rekeys private
channels under the *prior* root, and seeds the new Guestbook with a refounder
snapshot. `Refounding::execute` publishes in the mandated order and stops if the
root roll is not confirmed, so no compaction leaks out; every step is
idempotent so a failed run can be repeated. Proved on a self-made community: a
remaining member follows the rotation and folds the compacted plane to the same
roster, banlist and metadata with authors intact; staff receive the control
secret; the removed member is cut off and cannot open the new plane. Not yet
done: driving a Refounding from `ban_member`, and running any of this against a
live community.
A full status write-up of the Concord tranche, covering what was built, how it
was verified, findings and limits, is in
[`docs/CONCORD-STATUS.md`](docs/CONCORD-STATUS.md).
Concord Layer 3 sugar: `kick`, `ban` and `say ... in` are parser-level forms
lowering to `concord04.kick_member`, `concord04.ban_member` and
`concord01.publish_message`, with conformance fixtures, lowering tests and a
from-source execution test through the policy gate and Roster. Every Layer 3
form now reports `E1101` when incomplete rather than being dropped silently (a
wrapper over `parse_statement` and the `LAYER3_FORMS` list). The same flaw was
general, so the item loop now also reports any statement that fails without a
diagnostic and requires statements to end at a line boundary, `;` or `}`; leftover
tokens are no longer read as extra statements.
The read side and scoped grants still await RFC 0002.
Starting the RFC 0002 read side exposed a third silent-acceptance hole in the
checker: a call the checker could not resolve was simply not checked. Calling
an operation an imported module does not declare (`concord04.no_such_op(x)`),
or calling `concord04.kick_member(alice)` with no `use concord04`, passed
`check`, the second with no permission or arity check at all. Both are now
`E1101`. `ResolvedModuleGraph` gained a `known` set of every registered module
name so a forgotten `use` can be told from an ordinary identifier; a program's
own top-level names shadow module names.
RFC 0002 read side started: `concord01.stream(key) -> Stream` (with a
`StreamHandle` runtime value holding only the plane's public address), a
checked `conformance/valid/concord-read-stream.ns`, and `ChannelReader` in
`nscript-host-crypto`, which delivers only verified, channel-bound, unexpired,
unbanned, de-duplicated messages in canonical order (live: 7 real events
delivered once, 20 duplicates dropped). Blocked on the deferred handler
evaluator, on typing `event` from its source, and on how a script obtains a
key; the RFC's implementation notes record this.
Started the handler evaluator (`eval.rs`, documented in `docs/HANDLERS.md`): a
bounded tree-walking interpreter with typed `Value`s, scoped bindings,
arithmetic, comparisons, user functions, `me`, and module operation calls that
go through `OperationPolicy` via `RuntimeSession`. Proved end to end with a
moderation bot: real encrypted channel messages, `ChannelReader`, an NScript
handler (`if event.content contains "spam" { kick event.author }`), the real
moderation host, and an independent Guestbook fold. Now wired into `nscript run`: `--event`, `--events` and `--as` deliver
events to matching handlers in the simulator, with unimplemented operations
recorded and answered from their declared return type. Handler and function
bodies no longer run at startup (a handler's `kick event.author` used to fail
the whole run). `Result` values, `match`, `select` and in-handler publication
are not yet evaluated. Fixed a parser bug found on the way: a lowercase name before a block
(`if ready { .. }`) was read as a record literal.
Spec research (`docs/cord/FINDINGS.md`, specs vendored in `docs/cord/`) shows
the CORD-01 seal kinds and the CORD-02 community model need rework before
CORD-04: state is versioned editions, not ad-hoc events.

## Studio foundation: wasm compiler, capability footprint, and previews

The first slice toward a browser-based authoring surface (NScript Studio).
Studio itself is deferred; this tranche makes the compiler runnable in-browser
and exposes the security-relevant analysis it will render.

- `nscript-runtime` network hosts are now feature-gated: `rustls`/`tungstenite`
  and `RealRelayHost`/`RealRelayPool` live behind the default `real-hosts`
  feature. The fake-host runtime (relay, signer, clock, audit, storage, http,
  timer, log) compiles to `wasm32-unknown-unknown` with
  `default-features = false`, so dry-run and handler previews run client-side
  with no server.
- Added `crates/nscript-wasm`, a dependency-free JSON-in/JSON-out wasm ABI over
  linear memory (`nscript_alloc`, `nscript_dealloc`, `nscript_handle`,
  `nscript_free`, `nscript_abi`). Operations: `analyze`, `footprint`,
  `inspect`, `ir`, `compile`, `run`. Built-in modules are already embedded in
  the resolver, so analysis is fully offline. `scripts/wasm-conformance.sh`
  drives the whole `conformance/valid` + `conformance/invalid` corpus through
  the wasm artifact from Node.
- Added `CapabilityFootprint` to `nscript-semantics`: the inferred capability
  surface (effects + operation calls joined to module `effects`/`permission`
  plus publications, handlers, schedules) grouped into Nostr, Network,
  Payments, Storage, Secrets, and System, each item `granted`, `requested`, or
  `forbidden`. Computed from `infer`, so it is available live while permission
  errors still exist. `inspect --json` and the wasm `footprint`/`inspect`
  operations expose it; adding `zap ...` without `permissions { zap }` reports
  a `requested` payment capability.
- Added `Runtime::simulate_event` for the concrete fake-host runtime and
  `nscript test-event <file> --event <json>`: a synthetic signed event is
  queued on every lowered subscription and one handler cycle runs against the
  transactional/idempotency/logging fakes, reporting matched handlers,
  lowered subscriptions, log records, and committed storage.

### Studio foundation: editor analysis and the browser surface

- Added `crates/nscript-lang`: the editor-analysis surface. `analyze` owns the
  one resolution path (parse + custom modules + registry + resolve + structural
  checks), retaining every registered module name even when the current import
  does not resolve yet so a partial `use` line can still be completed.
  `symbols` lists top-level declarations for an outline; `completions` offers
  statement keywords, module names on a `use` line, module exports after
  `module.`, and typed `event.`/stream members resolved through the enclosing
  handler; `hover` explains modules, operations, functions, events, types, and
  the `Signed<…>` handler binding. Tested against the conformance corpus.
- `nscript-wasm` now delegates resolution to `nscript_lang::analyze` and
  exposes the editor ops the Studio needs: `symbols`, `completions`, `hover`,
  and `test_event` (the `simulate_event` evaluator path, with simulated module
  calls and per-handler failures reported instead of stopping the cycle). The
  node conformance harness exercises all of these through the real wasm
  artifact.
- Added `studio/`, the in-browser authoring surface: a Vite + Monaco editor
  that fetches the wasm compiler and renders diagnostics, the live capability
  footprint panel, module completions, hover cards, a synthetic-event preview,
  and a New Script template gallery. The wasm glue and panel logic are plain
  ESM and are exercised in node (`studio/tests/core.test.mjs`) without a
  browser; `npm run build` produces the deployable static site.

## Deferred

Module operation dispatch, full handler/stream evaluation (a core evaluator now
exists; see `docs/HANDLERS.md`),
cryptographic signing, NIP-44/NIP-59/NIP-46 host implementations, signed
package distribution, and a stable IR interchange format remain later phases.
