# NScript

NScript is a purpose-built, statically typed scripting language for Nostr.
It makes events, filters, relays, signers, permissions, and NIP-defined
behaviour language concepts instead of SDK conventions.

```nostr
use nip01
use nip46

signer account = nip46()
relayset public = configured

permissions {
    read Note
    publish Note
    sign Note with account
    relay public
}

publish Note {
    content: "Hello, Nostr"
} to public with account
```

NScript is specification-led, with a working Rust compiler and reference
runtime. The current Draft 0.1 surface is broad; the next phase is focused on
making one real application workflow dependable from authoring through
deployment.

The Rust front end parses and statically checks the Draft 0.1 source corpus,
emits inspectable IR and manifests, and supports both deterministic simulation
and a real relay/signer deployment loop. Module operations without a configured
real host remain simulated by `deploy`:

```bash
cargo run -p nscript-cli -- check conformance/valid/default-publish.ns
cargo run -p nscript-cli -- run conformance/valid/hello-note.ns
cargo run -p nscript-cli -- run conformance/valid/nip44-call.ns
cargo run -p nscript-cli -- run conformance/valid/nip17-send.ns
cargo run -p nscript-cli -- compile --emit ir conformance/valid/hello-note.ns
cargo run -p nscript-cli -- module check conformance/modules/valid/nip10.nsm
cargo run -p nscript-cli -- module hash conformance/modules/valid/nip10.nsm
cargo run -p nscript-cli -- module describe conformance/modules/valid/nip10.nsm
cargo run -p nscript-cli -- test-event conformance/valid/handler-print.ns --event '{"kind":1,"content":"hello"}'
cargo run -p nscript-cli -- inspect --json examples/concord-moderation-bot.ns
cargo run -p nscript-cli -- run examples/concord-moderation-bot.ns --event '{"content":"buy spam now","signer":"mallory"}'
```

The compiler front end also builds to `wasm32-unknown-unknown` for in-browser
authoring. `scripts/wasm-conformance.sh` builds the artifact and runs the full
`conformance/valid` and `conformance/invalid` corpus through the wasm ABI with
Node.

Additional modules are resolved locally from deterministic
`<root>/<module>/<version>.nsm` layouts:

```bash
cargo run -p nscript-cli -- check -M ./my-modules program.ns
```

The built-in module graph now includes typed NIP-44 encryption, NIP-59 gift
wrapping, and NIP-17 private-message contracts. These modules declare the
protocol types and required effects; host implementations remain capability
bound and are not given raw private keys. Runtime operation dispatch checks an
explicit capability policy before invoking any module host operation, and
checked source calls can now be executed through that boundary.

Constructed module arguments retain their nominal record name and recursively
typed fields when crossing from checked source into the runtime. This keeps
source-level forms such as `PrivateMessage { ... }` distinct from untyped JSON
while allowing hosts to normalize and validate scalar NIP records at the
capability boundary.

NIP-19 identifiers also have a pure typed host path: valid `npub`, `nprofile`,
`nevent`, and `naddr` Bech32 values are checksum-verified before becoming
nominal identifier values; `npub` can then convert to a nominal `PubKey`.

NIP-65 relay preferences are represented as a typed `RelayList` and published
through an explicit `Sign`/`Relay` capability operation.

NIP-78 application data is represented as typed addressable `AppData` and
published through the same explicit capability boundary.

NIP-02 follow lists use a typed `FollowList` value and an explicit
`Sign`/`Relay` publication operation.

NIP-25 reactions use a typed `Reaction` value with a nominal target `EventId`
and the same explicit publication boundary.

NIP-09 deletion is modeled as a typed `DeletionRequest`, preserving the fact
that relays may accept or ignore the request.

NIP-51 user lists use a typed `UserList` with nominal `PubKey` members and an
explicit signed publication operation.

NIP-57 zaps produce a typed `PaymentIntent` through an explicit payment effect;
creating a request does not silently authorize a transfer.

NIP-52 calendar events use typed timestamps and reject inverted start/end ranges
before publication.

NIP-66 relay monitoring uses typed `RelayStatus` values and validates uptime and
latency bounds before publication.

NIP-5A site deployment uses typed `SiteDeployment` values and explicit
storage/signing/relay capabilities; it does not grant ambient filesystem or
shell access.

NIP-10 replies use typed root and target references. `nip10.publish_reply`
lowers a checked `Reply` record to reply-tag semantics through an explicit
signing/relay capability.

NIP-18 reposts use typed `Repost` records. `nip18.publish_repost` lowers the
target reference through the same explicit signing/relay capability boundary.

NIP-22 comments use typed `Comment` records with arbitrary event targets.
`nip22.publish_comment` validates and lowers the target/content pair through an
explicit signing/relay capability.

NIP-23 long-form content uses typed addressable `Article` records.
`nip23.publish_article` validates the identifier, title, and body before
publication through an explicit signing/relay capability.

NIP-29 group messages use typed `GroupMessage` records with explicit group
scope. `nip29.publish_group_message` validates the scope before publication
through the signing/relay capability boundary.

NIP-32 labels use typed `Label` records with explicit namespace and value
fields. `nip32.publish_label` validates classification metadata before
publication through the signing/relay capability boundary.

NIP-37 drafts use typed `Draft` records with explicit storage, signing, and
relay effects. `nip37.save_draft` validates draft identity and content before
staging publication.

NIP-38 user status uses typed `UserStatus` records for presence and activity.
`nip38.publish_status` validates the status and content through an explicit
signing/relay capability.

NIP-42 relay authentication is exposed as the typed `nip42.authenticate`
runtime primitive. It validates secure relay URLs and requires an explicit
relay-auth capability before returning an authenticated session.

NIP-45 event counts use `nip45.count_events` to return an aggregate integer
 from a validated filter without downloading the matching events.

NIP-50 search uses typed `SearchRequest` and `SearchResults` values.
`nip50.search_events` validates query intent and delegates result retrieval to
the relay capability.

NIP-53 live events use typed addressable `LiveEvent` records.
`nip53.publish_live_event` validates the identifier and descriptive fields
before publication through an explicit signing/relay capability.

NIP-56 reports use typed `Report` records with explicit target, category, and
rationale fields. `nip56.publish_report` validates moderation signals before
publication through an explicit signing/relay capability.

NIP-58 badges use typed `Badge` records for credentials and memberships.
`nip58.publish_badge` validates the identifier and descriptive metadata before
publication through an explicit signing/relay capability.

NIP-68 image events use typed `ImageEvent` records. `nip68.publish_image`
validates media URL and caption fields before publication through an explicit
signing/relay capability.

NIP-71 video events use typed `VideoEvent` records. `nip71.publish_video`
validates media URL and caption fields before publication through an explicit
signing/relay capability.

NIP-77 synchronization uses typed `SyncRequest` and `SyncResult` values.
`nip77.synchronize` validates secure relay/cursor inputs and keeps Negentropy
transport behind explicit relay/storage capabilities.

NIP-84 highlights use typed `Highlight` records for reading and annotation
workflows. `nip84.publish_highlight` validates source and content before
publication through an explicit signing/relay capability.

NIP-85 trusted assertions use typed `Assertion` records for trust and
reputation signals. `nip85.publish_assertion` validates subject, kind, and
value before publication through an explicit signing/relay capability.

NIP-86 relay management uses typed `RelayAdminRequest` values.
`nip86.manage_relay` validates the relay/action/subject tuple and requires an
explicit relay-admin capability.

NIP-89 application handlers use typed `AppHandler` records to advertise event
routing. `nip89.publish_handler` validates kind, application, and endpoint
before publication through an explicit signing/relay capability.

NIP-94 file metadata uses typed `FileMetadata` records. The
`nip94.publish_file_metadata` operation validates URL, MIME type, and content
hash before publication through an explicit signing/relay capability.

NIP-B7 Blossom storage uses typed `BlobUpload` and `BlobStored` values.
`nipb7.upload_blob` validates content-addressed uploads behind explicit
storage/HTTP capabilities.

NIP-98 HTTP authentication uses typed `HttpAuthRequest` and
`AuthenticatedRequest` values. `nip98.authenticate_http` validates secure URLs
and methods behind explicit signing/HTTP capabilities.

NIP-47 wallet payments use typed `WalletPayment` and `PaymentResult` values.
`nip47.pay_invoice` validates invoices and positive amounts behind an explicit
`Payment` capability; payment authorization is never ambient.
Policies can additionally constrain payment authority with
`allow_payment_up_to`, which rejects over-budget requests before host dispatch.

NIP-46 provisioning returns a typed `SignerSession` capability through the
operation host. Scripts receive a remote signer handle rather than private key
material.
Real hosts can implement the dedicated `SignerProvisionHost` adapter, whose
runtime entry point records provisioning in the audit stream.
Authenticated relay hosts can similarly implement `RelaySessionHost`; its
runtime entry point validates the session through the adapter and records the
authentication attempt in the audit stream.
NIP-98 requests can then run through an allowlisted `HttpHost` adapter via
`Runtime::execute_http`, with the request recorded in the audit stream.
Stateful hosts can implement `TransactionalStorageHost` so
`Runtime::storage_transaction` stages writes and commits them only when the
script operation succeeds; failed transactions are discarded and audited as
`rolled_back`.
Timer declarations can be handed to a host through `TimerHost` and
`Runtime::schedule_timer`, preserving deterministic schedule metadata while
keeping wakeups and civil-time policy outside the script.
The semantic checker now emits schedule descriptors for literal `every` and
`at` declarations, and `Runtime::schedule_program` registers them in order.
Idempotent handlers can use `IdempotencyHost` and `Runtime::claim_once` to
atomically claim event IDs; duplicate deliveries return `false` and are
audited without rerunning the handler.
Stream and query lowering can use `SubscriptionHost` and `Runtime::subscribe`
with typed event filters, keeping relay lifecycle and transport policy in the
host runtime. `Runtime::unsubscribe` closes those handles through the same
audited capability boundary.
`Runtime::poll_subscription` drains typed event batches and preserves
EOSE-like completeness metadata for stream consumers.
The runtime also suppresses repeated signed-event IDs across relay retries
before batches reach script handlers.
Subscription filters may include an explicit relay set, keeping relay routing
policy visible to the host and auditable at stream creation.
They also carry typed event kinds and tag-equality predicates, avoiding raw
JSON filter construction.
The runtime enforces a configurable maximum batch size (1024 by default) to
bound relay-driven memory and handler work.
`Runtime::poll_and_claim` combines that bound with atomic event-ID claims for
duplicate-safe stream handlers.
Subscription requests and batches carry opaque typed cursors so hosts can
resume relay streams after reconnects without exposing transport details.
Structured output goes through the bounded `LogHost`/`Runtime::log` boundary,
with oversized messages rejected and outcomes audited.
Storage transactions now snapshot committed values for reads, while writes
remain staged until successful completion.

## Repository map

- [`ROADMAP.md`](ROADMAP.md) records the current product and release priorities.
- [`PLAN.md`](PLAN.md) records the implementation history and original phase plan.
- [`spec/`](spec/) contains the normative language and runtime specification.
- [`rfcs/`](rfcs/) contains companion proposals, including package distribution.
- [`conformance/`](conformance/) contains executable examples and negative tests
  for future implementations.
- `crates/` contains the Rust syntax, semantics, IR, reference runtime, CLI front
  end, a WebAssembly build of the compiler front end for in-browser tooling, and
  `nscript-lang`, the editor-analysis surface (symbols, completions, hover).
- [`studio/`](studio/) is the in-browser authoring surface: a Monaco editor that
  runs the wasm compiler locally with live diagnostics, a permission footprint
  panel, and a synthetic-event preview.

## Status

NScript is an evolving Draft 0.1 implementation. The compiler, simulator,
package metadata and lockfile commands, browser Studio, and a real relay/signer
deployment loop exist. The deployment loop does not yet execute general NIP
module operations against real hosts; those operations are simulated unless a
host implementation is explicitly wired in. Concord protocol operations have
real Rust host implementations and end-to-end tests, but are not yet available
as a configured `nscript deploy` host.

The runnable [`examples/layer3-bot.ns`](examples/layer3-bot.ns) demonstrates
the current language-facing Layer 3 surface: typed event patterns, native
publication syntax, local event bindings, conditions, logging, and early
returns. It uses Nostr capabilities without manually constructing wire tags or
JSON.

The [`Concord moderation bot`](examples/concord-stream-moderation-bot.ns) shows
the encrypted-stream handler shape. [`docs/CONCORD-BOT.md`](docs/CONCORD-BOT.md)
explains what runs in simulation, what is covered by the real-host integration
tests, and what the live CLI runner still needs.

## Design principles

1. Nostr is the environment, not a library.
2. Nostr values are nominally typed, even when their wire encodings coincide.
3. Signing and other authority flow through explicit capabilities.
4. Source programs declare permissions; the compiler infers effects.
5. NScript lowers to existing Nostr protocols rather than inventing a new wire
   protocol.

## Contributing

Design changes should begin as an issue or RFC and include conformance examples.
Normative terms such as **MUST**, **SHOULD**, and **MAY** follow RFC 2119 usage.

Run `./scripts/check-spec.sh` before submitting a change. It validates the local
documentation links, JSON vectors, negative-fixture metadata, and whitespace.

## License

NScript is available under the [MIT License](LICENSE).
