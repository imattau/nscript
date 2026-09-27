# NCC integration plan

This plan records how Nostr Community Conventions from
[`imattau/nostr-community-conventions`](https://github.com/imattau/nostr-community-conventions)
are incorporated into NScript. It follows the design intents in `README.md`
(nominal typing, explicit capabilities, declared permissions, lowering to
existing protocols) and the workflow-first rule in `ROADMAP.md` (no protocol
breadth without a concrete workflow and conformance need).

The NCC repository is pinned at commit
`186c3ad50966a2319c354ace12e0a5a2267b75d9`. A release MUST record a new pin
when NCC lowering behaviour changes, mirroring the NIP review-commit rule in
[`spec/README.md`](spec/README.md).

## Reviewed conventions

| NCC | Kinds | Depends on | Core surface |
| --- | --- | --- | --- |
| 00 | 30050 doc, 30051 succession, 30052 endorsement, 30053 supporting doc | — | Meta-convention: publishing and revising NCC documents on Nostr |
| 02 | 30059 service record, 30060 attestation, 30061 revocation | — | Endpoint identity binding (`u`/`k`/`exp`) and optional attestation trust |
| 03 | definition 36998, vote 1071, roll 36997, audit 36999 | — | Elections, votes, one vote per pubkey, voting window |
| 05 | 30058 locator | 02 (anchored mode) | Encrypted `ip:port` locators, TTL freshness, endpoint ordering |
| 06 | none (behaviour only) | 02 + 05 | Client/sidecar conflict, caching, and transport policy |
| 07 | 30062 manifest | composes 02/05 | `d=capabilities` with repeatable `cap` tags |
| 08 | 1070 proposal + acceptance | 02 (service scope) | Two-event identity handover with chains and conflict rules |
| 09 | 30064 authority grant | 02 (service scope) | Scoped operator authority: `d=<service-id>:<operator>`, `service`, `p`, `status` (`active`/`revoked`), repeatable `scope` tags, optional `expiration`/`valid_from` |
| 10 | 30065 state | 02 (service id); optionally 09 | Operational state (`operational`/`degraded`/`maintenance`/`unavailable`/`retiring`), direct `d=<service-id>` or operator `d=<pubkey>:<service-id>` + three-column `operator_for` |
| 11 | 30067 policy | 02 + 05 (rules over both); 09/10 rule namespaces | Portable trust policy: named `d`, three-column `rule <key> <value>` and `trust certifier <pubkey>`, private rules NIP-44-encrypted in `content` |
| 13 | 30063 release (profiles NIP-51); 32267/30617/1063 referenced, not owned | composes 07 (advert), 08 (successor identity), 09 (`ncc:13:publish` operator scope) | Package-manager semantics over an existing NIP-51 Release Artifact Set: `version`/`version_scheme`/`channel`, two-column `requires`/`optional`/`conflicts`, `source`/`commit` provenance, and `os`/`arch`/`format` artefact selectors added to the NIP-94 artefacts it references |

The table covers every convention the pin contains — ten reviewed and all
scheduled below. Upstream has never contained `ncc-01`, `ncc-04` or `ncc-12`
— checked against the repository's full history — so those gaps are
upstream's own numbering, not conventions this plan skipped.

## Upstream prerequisites

Both defects originally recorded here were fixed in the NCC repository
itself, in `3a45e72` (merged as `fe5981f`) — the reason the pin above moved
off `71238583`. They are kept for the record because each one gated a stage:

1. **NCC-02 kinds 30060 and 30061 declared no `d` tag** while sitting in the
   30000–39999 addressable range. Without `d`, every attestation and
   revocation from one certifier replaces every other at `d=""`. Fixed
   upstream: both events now require `d` (`<srv>:<subj>` for 30060, the
   revoked attestation's event id for 30061) and §2/§3 state the
   addressability rationale. Stage 3 implements the fixed text.
2. **NCC-03's kind model was unresolved**: the Election Definition kind was
   not normatively stated, §5.1 said "non-replaceable" while the companion
   library emitted an addressable kind, and the electoral roll's kind 30000
   overlapped NIP-51 legacy list space. Fixed upstream: definition `36998`,
   vote `1071` (regular), electoral roll `36997`, audit `36999` are normative
   and the library matches them. NCC-03 is still deferred in `ROADMAP.md`,
   now on surface size and its Concord-governance dependency rather than on
   an upstream defect.

## Pin history

The pin has moved three times, each move recorded here:

- `71238583` → `fe5981f` before stage 3: upstream `3a45e72` added the `d`
  tag NCC-02's addressable events were missing and made NCC-03's kinds
  normative (Prerequisites above).
- `fe5981f` → `adad778` before stages 8–10: upstream added NCC-09, NCC-10
  and NCC-11. The drift is purely additive — 6904 insertions across 32
  files with 0 deletions, every one inside the new `ncc-09`/`ncc-10`/
  `ncc-11` folders or the repository index `README.md` — so no convention
  lowered by stages 1–7 changed text, and every module and vector reference
  moved to the new commit.
- `adad778` → `186c3ad` before stage 11: upstream added NCC-13. Again
  purely additive — every new file sits under `ncc-13/` or the repository
  index `README.md` — so no convention lowered by earlier stages changed
  text.

Stages 8–10 also needed an infrastructure step the earlier stages did not:
NCC-10's `operator_for` and NCC-11's `rule`/`trust certifier` are
three-column wire tags, while the runtime event model carried only
`(name, value)` pairs. A tag value now carries further columns joined by
U+001F (unit separator); `wire_tags` splits them onto the wire and parsing
rejoins them, so a three-column tag round-trips and a two-column tag is
unchanged (`spec/language.md` §3, `docs/HANDLERS.md`).
## Phase 0 — groundwork

**0a. Namespace and pinning.** Reserve the `ncc` module namespace
(`modules/std/nccXX/0.1.0.nsm`, `reference` pointing at the pinned NCC
commit). Record the pin in [`spec/README.md`](spec/README.md).

**0b. Spec scaffolding.** Add a "Community conventions" section to
[`spec/nostr.md`](spec/nostr.md) covering module naming, kind ranges, revision
pinning, and the rule that NCC modules use the ordinary typed-module contract
(no new syntax).

**0c. ROADMAP.** Add the community-conventions phase with per-NCC exit
criteria (see [`ROADMAP.md`](ROADMAP.md)).

**0d. Real wire lowering for declared events.** *(Done — implemented as
described below.)* The general path from a
`publish <record>` statement to signed wire data previously kept only `content`
and hardcoded `kind: "Note" => 1`, with empty tags. It now implements the
already-specced contract:

- `.nsm` `event` declarations carry kind, mode, content encoding, and the
  allowed tag union (`spec/modules.md`).
- A record's author fields lower to two-column wire tags named after the
  field: scalars (`Text`, `Int`, `Bool`, `PubKey`) render as text, a `List`
  field repeats the tag per element, `content` is the event body, and `tags`
  plus the bookkeeping fields (`id`, `author`, `pubkey`, `kind`,
  `created_at`) never lower (they are read-side only).
- A parameterised event's identifier field renames to the single `d` tag,
  enforced to appear exactly once (`CheckedEvent::lower_tags`).
- Kind and replacement mode resolve from `CheckedProgram::events`: the
  program's own `event` declarations plus every imported module's, merged by
  `bind_module_events` (the program shadows its modules) at every
  check-executing call site — CLI run/inspect/ir/deploy/test-event, the WASM
  equivalents, and every `dispatch_evaluated` call. The historical fallback
  (`Note` is kind 1, anything else kind 0) remains only for names nothing
  declares, so bare scripts keep publishing what they always did.
- Top-level `publish` carries only fields written as literals, because
  top-level statements do not execute at startup (pre-existing architecture;
  a computed top-level field drops silently — see follow-ups). A handler's
  own `publish` lowers evaluated values live and fails loudly on non-scalars.
- The normative rule lives in `spec/language.md` §3 (with a scope note in
  `spec/modules.md`'s Wire lowering section); module tag unions are declared
  but not yet applied by the core publish path.

Module *operation* calls (for example `nip78.publish_app_data`) stay
simulated exactly as they are today; only `publish` statements and declared
event paths claim wire-real behaviour.

**0e. Decode-path verification.** *(Done.)* In the `deploy` subscription
path each handler's declared kind — resolved from `CheckedProgram::events`
(program plus imported module declarations) with the module-graph lookup as
fallback — is written into the subscription request, so the relay filter
carries it; after delivery, the poll loop's kind re-check drops anything a
relay sent anyway, and `matches_subscription` re-checks the same kind before
the body runs. `RealRelayHost::parse_event` additionally requires the wire
fields before an event exists at all. Covered end to end by
`deploy_filters_delivered_events_by_the_declared_kind`: a hostile relay
delivers a wrong-kind impostor wearing the trigger tag ahead of the real
Note, and only the real Note dispatches. Receipt-time content-encoding and
tag-union validation does not run (the spec does not require it; declared
validators are script-invoked pure functions, not implicit dispatch gating).

## Follow-ups recorded from 0d

- Algebraic/typed `tags:` lowering (`Person(alice)` and friends) and
  positional wire fields: the core publish path lowers name/text pairs only,
  so module-declared tag unions are not applied yet.
- `json<T>` and other named content encodings on core `publish`: content is
  text today.
- Publish-field validation diagnostics: a non-literal top-level field drops
  silently, and fields unknown to the event's declared tag union pass
  unchecked (`E1201` only validates kind vs. mode). Related: an addressable
  module event's `d` conformance (for example `ncc07`'s `require
  manifest_identifier(d)`) is declarative only — event `require` lines are
  parsed and hashed but never evaluated, so `d=capabilities` rides on this
  same gap rather than being runtime-enforced. Needs spec decisions before
  codes are minted.
- `nscript-ir` / WASM `create_event` carrying lowered tags: kind already
  prefers `CheckedProgram::events`, but the IR executor still signs with an
  empty tag list.
- Route `send <record>` through the lowering once NIP-17 encrypt-and-gift-wrap
  lands; it stays deliberately `OperationUnavailable` until then.

## Stages

Each stage ships the full recipe: `.nsm` module registered in `BUILTINS`,
runtime records and dispatch, pure functions for selection/validation that take
`now` from the caller (validators may not read time), valid and invalid
conformance fixtures, a JSON wire vector, a `conformance/MATRIX.md` row, a
`spec/nostr.md` subsection, a worked example, and a documented infrastructure
adoption (or an explicit non-adoption note).

| Stage | NCC | Rationale for position | Infrastructure adoption |
| --- | --- | --- | --- |
| 1 | NCC-07 | Smallest surface; first exercise of the 0d lowering path | A deployed bot publishes and refreshes its own capability manifest |
| 2 | NCC-00 | Document lifecycle governs how later stages pin revisions | NScript records which NCC revisions it implements as queryable data |
| 3 | NCC-02 | Anchor for 05/06/08; first clock-bound validity | Services publish service records; monitors validate them |
| 4 | NCC-05 | First encrypted payload; composes `nip44` | Services refresh encrypted locators on address change |
| 5 | NCC-06 | Behaviour composed from stages 3 and 4 | Identity-first endpoint resolution in deploy/monitor workflows |
| 6 | NCC-08 | Multi-event state machine after the anchor exists | Documented bot identity rotation workflow |
| 7 | NCC-03 | Largest surface; four event kinds and a Concord-governance dependency, so it lands last | Builds on `poll-tally-bot.ns` and Concord governance |
| 8 | NCC-09 | Delegated authority the service cluster builds on; needs the pin bump | Principals publish scoped, time-bounded operator grants |
| 9 | NCC-10 | Current state over the same service identity; composes stage 8 | Services and their authorised operators publish operational state |
| 10 | NCC-11 | Policy data over the whole service stack | Clients and agents read one portable trust policy |
| 11 | NCC-13 | Composes 07/08/09 and profiles NIP-51/94/34 rather than owning new kinds, so it lands after the service cluster it cites; needs the pin bump | A release monitor judges upgrade eligibility, dependency and conflict declarations, and platform-matching artefacts over a published Release Artifact Set |

## Stage 1 — NCC-07 capability manifest *(Done)*

Shipped the full recipe against the pinned commit:

- **Module** `modules/std/ncc07/0.1.0.nsm`, registered in `BUILTINS`, with
  `reference` pinned to the convention README. It declares the
  `CapabilityManifest` event (kind 30062, `mode: addressable`, `content` as
  text, `d` and `cap` fields, `require manifest_identifier(d)`, and the
  `CapabilityTag` wire union `["cap", <id>]`), plus four pure functions:
  `capabilities` (extract `cap` identifiers from the handler-side
  `name=value` tag rendering), `supports` (exact membership),
  `capability_namespace` (`nip`/`ncc`/`pubkey`/`opaque`, so a broken
  `nip:abc` classifies as `opaque`), and `capability_is_valid` (a known
  namespace prefix must be completed, or the identifier is invalid). None
  read the clock; NCC-07 has no time-bound rules, so no `now` parameter is
  needed.
- **Runtime dispatch** in `nscript-runtime`'s shared pure-function registry,
  so every host answers identically, with unit tests for extraction,
  membership, classification, validation, and wrong argument shapes.
- **Fixtures**: `conformance/valid/ncc07-manifest.ns` (publishes a manifest
  and reads peer manifests in a handler) and
  `conformance/invalid/ncc07-regular-mode.ns` (re-declares kind 30062 as a
  regular event → `E1201 invalid-event-declaration`).
- **Wire vector** `conformance/vectors/ncc07.json` (kind 30062, `d=capabilities`,
  three `cap` tags), asserted against the `inspect --json` publication trace
  by a CLI test.
- **Worked example** `examples/ncc07-capability-bot.ns`: the only `publish`
  sits inside `every 24h { }`, which runs once at startup (initial publish,
  timer registered) and again each tick (refresh); a `where tags.d contains`
  handler selects incoming capabilities with the pure functions. Exercised
  end to end by a CLI run test with and without `--event`.
- **Matrix row** and **spec subsection** (`spec/nostr.md` → Community
  conventions → NCC-07 capability manifests).
- **Infrastructure adoption**: a deployed bot publishes and refreshes its own
  capability manifest — exactly what `examples/ncc07-capability-bot.ns` does
  (startup publish + 24h refresh), so any deployed instance of this bot is
  running the adopted workflow. The convention's own warning is recorded in
  the example header and spec: a manifest is an advertisement, never proof of
  what the publisher implements.

Known scope limits (inherited from 0d, restated): `d=capabilities` conformance
is declarative (event `require` lines are not evaluated), and the module tag
union drives lowering via `lower_tags` but unknown publish fields still pass
unchecked — see follow-ups above.

## Stage 2 — NCC-00 document lifecycle *(Done)*

Shipped the full recipe against the pinned commit:

- **Module** `modules/std/ncc00/0.1.0.nsm`, registered in `BUILTINS`, with
  `reference` pinned to the convention README. It declares four addressable
  events — `NccDocument` (kind 30050: `d`, `title`, `published_at`,
  `status`), `NccSuccession` (kind 30051: `d`, `authoritative`),
  `NccEndorsement` (kind 30052: `d`, `endorses`), and
  `NccSupportingDocument` (kind 30053: its own per-author `d`, `for`,
  `title`, `published_at`, `status`) — plus three validators
  (`ncc_identifier`, `ncc_status`, `event_reference`) and six pure
  functions: `identifier`/`status` extract from the handler-side
  `name=value` tag rendering, `identifier_is_valid`/`status_is_valid` check
  §A.5's prefix and four statuses, `succession_is_effective(tags, now)`
  judges effectiveness against a caller-supplied clock (absent
  `effective_at` is in force from authoring; malformed never is), and
  `authority_label` renders Appendix B's `Steward-acknowledged` /
  `De-facto (adopted)` labels — display guidance, never a permission.
- **Runtime dispatch** in `nscript-runtime`'s shared pure-function registry,
  with unit tests for extraction, validity, effectiveness, labels, and wrong
  argument shapes.
- **Fixtures**: `conformance/valid/ncc00-ledger.ns` (publishes an
  implementation supporting document and reads documents and successions)
  and `conformance/invalid/ncc00-succession-wrong-type.ns`
  (`succession_is_effective(event.tags, event.content)` → `E1001
  nominal-type-mismatch`: scripts hold no wall clock, so the caller must
  pass an `Int` timestamp).
- **Wire vector** `conformance/vectors/ncc00.json` (kind 30053, six tags in
  construct order), asserted against the `inspect --json` publication trace
  by a CLI test.
- **Worked example** `examples/ncc00-implementation-ledger.ns`: watches
  kind 30050 and, for each revision NScript implements, stamps an
  authority-free kind-30053 record — `published_at` taken from the delivered
  event's `created_at`. Exercised end to end by a CLI run test with no
  event (nothing publishes), an implemented document (record published), and
  an unimplemented one (handler stays quiet).
- **Matrix row** and **spec subsection** (`spec/nostr.md` → Community
  conventions → NCC-00 document lifecycle).
- **Adoption (open decision 3 resolved)**: NScript publishes no kind-30050
  document of its own — that would claim stewardship of a convention it does
  not author. The implemented-revisions record ships as the example bot's
  kind-30053 supporting documents; Appendix E makes those authority-free, so
  the ledger is evidence of adoption, never an approval or a capability.

Scope notes (same gaps as 0d): event `require` lines are declarative and
never evaluated, and unknown publish fields still pass unchecked — the
module's required-tag discipline rides on the shared lowering path rather
than runtime enforcement.

## Stage 3 — NCC-02 endpoint identity binding *(Done)*

The pin moved from `71238583` to `fe5981f` before anything else landed:
upstream `3a45e72` added the `d` tag NCC-02's two addressable events were
missing (prerequisite 1) and made NCC-03's kinds normative (prerequisite 2).
The `ncc-00` and `ncc-07` READMEs are byte-identical across the move, so no
convention text recorded in earlier stages changed meaning. Shipped the full
recipe against that commit:

- **Module** `modules/std/ncc02/0.1.0.nsm`, registered in `BUILTINS`, with
  `reference` pinned to the convention README. It declares three addressable
  events — `ServiceRecord` (kind 30059: `d`, `u`, `k`, `exp`),
  `CertificateAttestation` (kind 30060: `d`, `subj`, `srv`, `e`, `std`,
  `lvl`, `nbf`, `exp`), and `Revocation` (kind 30061: `d`, `e`, `reason`) —
  plus two validators (`present`, `known_trust_level`) and eight pure
  functions: `service_id`/`endpoint`/`transport_key`/`trust_level` extract
  from the handler-side `name=value` tag rendering; `endpoint_scheme`
  classifies an endpoint's `scheme://` prefix, returning empty text when it
  is absent or malformed; `record_is_valid(tags, now)` requires `d`, `k`,
  and an `exp` that has not passed — `u` deliberately is not required, so a
  private or invite-only service keeps the record as its identity anchor;
  `attestation_is_valid(tags, now)` additionally requires every attestation
  tag, the `<srv>:<subj>` scoping of `d`, one of §2's three trust levels,
  and `nbf <= now < exp`; and `revocation_is_for(tags, attestation_id)`
  matches the required `e` reference, so a matching revocation withdraws an
  attestation whatever its own `exp` says (§3, revocation overrides expiry).
- **Runtime dispatch** in `nscript-runtime`'s shared pure-function registry,
  with unit tests for extraction, scheme classification, both validity
  windows (expiry boundary, private record, missing and malformed tags,
  unscoped and out-of-window attestations), revocation matching, and wrong
  argument shapes. The tag readers were factored out of `ncc00`'s helpers
  into a shared `tag_value`/`tag_lookup`, so both conventions read
  `name=value` tags through one path.
- **Fixtures**: `conformance/valid/ncc02-service-record.ns` (publishes a
  record and validates delivered ones against `event.created_at`) and
  `conformance/invalid/ncc02-validity-wrong-clock.ns`
  (`record_is_valid(event.tags, event.content)` → `E1001
  nominal-type-mismatch`: scripts hold no wall clock, so the caller must
  pass an `Int` timestamp).
- **Wire vector** `conformance/vectors/ncc02.json` (kind 30059, four tags in
  construct order), asserted against the `inspect --json` publication trace
  by a CLI test.
- **Worked example** `examples/ncc02-service-registry.ns`: publishes its own
  record from `every 7d { }`, then judges the records, attestations, and
  revocations it receives. The trust store is a `let` inside the handler
  that reads it, because a top-level `let` is not visible in a handler. Run
  end to end by a CLI test with no event (startup publish), a valid and an
  expired record, a trusted and an untrusted attestation, and the revocation
  of the relied-upon attestation.
- **Matrix row** and **spec subsection** (`spec/nostr.md` → Community
  conventions → NCC-02 endpoint identity binding).
- **Infrastructure adoption**: services publish service records; monitors
  validate them — exactly what the example does, so any deployed instance
  runs the adopted workflow. The convention's limits are recorded in the
  example header and the spec: the record asserts the endpoint/key binding
  while the client still performs it, and trust policy (which certifiers,
  which levels, whether attestations are required) stays script-visible data.

Scope notes (same gaps as 0d): event `require` lines are declarative and
never evaluated, so `record_is_valid` — not the event declaration — is what
enforces `d`/`k`/`exp` at runtime, and unknown publish fields still pass
unchecked. Two limits of this stage: a schedule body is not executed under
`nscript run` (its `publish` is collected as a startup publication, but the
statements around it run only when a timer fires), and NCC-02's resolution
step 7 — connect, then compare the observed transport key against `k` — is
not something a script can do, so no function here claims to have done it.

## Stage 4 — NCC-05 encrypted locators *(Done)*

The first encrypted payload, composing `nip44` rather than adding a host
capability of its own. Shipped the full recipe against the pin of the day,
`fe5981f`:

- **Module** `modules/std/ncc05/0.1.0.nsm`, registered in `BUILTINS`, with
  `use nip44 @ "^0.1"` and a `reference` pinned to the convention README. It
  declares one addressable event — `Locator` (kind 30058: required `d`,
  optional `expiration` and `private`, `content: EncryptedText`) — plus one
  validator (`present`) and eight pure functions: `locator_name` extracts
  the `d` destination; `endpoint_object`/`endpoint_family` build and
  classify §5.4 endpoints (empty text when the URL's own spelling does not
  decide the family, since guessing would move it in §7's order); `payload`
  renders the §5.3 document, refusing — with empty text — a non-positive
  `ttl` or an endpoint that does not parse, and omitting `caps` when empty;
  `payload_endpoints`/`payload_caps` read them back, endpoints ordered into
  §7's attempt order (ascending priority with §5.4's default of 1000, then
  `onion`, `ipv6`, `ipv4`, then the URL); `payload_is_fresh` reports
  `now <= updated_at + ttl`; and `record_is_fresh` requires `d`, a payload
  that is itself fresh, and an `expiration` not yet passed, so §8's earlier
  deadline is what a record is judged against.
- **Publish lowering** for encrypted content: `publish` accepts an
  `EncryptedText` value as `content` and carries the envelope whole rather
  than failing for content that is not text (`eval.rs`, beside the text
  case). The wire vector pins the other half — a handler-computed payload
  reaches `inspect --json` as `content: null`, because the checked snapshot
  holds only literal tags.
- **Runtime dispatch** in `nscript-runtime`'s shared pure-function registry,
  with unit tests for endpoint building and parsing, the family
  classification table, payload construction and its failures, §7 ordering,
  freshness boundaries (`now == updated_at + ttl` still fresh, one second
  later is not, `ttl <= 0` never is), record judgment against both
  deadlines, and wrong argument shapes.
- **Fixtures**: `conformance/valid/ncc05-locator.ns` (a handler that
  rebuilds a peer's payload, encrypts it, and publishes its own Locator,
  then judges delivered ones) and `conformance/invalid/ncc05-locator-wrong-clock.ns`
  (`payload_is_fresh(event.tags, ...)` → `E1001`, since the payload argument
  must be `Text`, not the event's tags).
- **Wire vector** `conformance/vectors/ncc05.json` (kind 30058, `d` and
  `expiration` tags, `content: null`), asserted against the `inspect --json`
  publication trace by a CLI test.
- **Worked example** `examples/ncc05-locator-bot.ns`: validates a peer's
  Service Record with `ncc02`, rebuilds the payload from it, NIP-44-encrypts
  it to the record's owner, and publishes a Locator whose `expiration` is
  one day from the delivered record's `created_at`; a reader discards any
  Locator that is expired, unaddressed, or whose payload it cannot read.
  Run end to end by a CLI test with no event, a valid and an expired record,
  a plaintext Locator (§5.2), a stale payload, and an encrypted envelope a
  reader cannot open — the fail-closed case the stage exists for.
- **Matrix row** and **spec subsection** (`spec/nostr.md` → Community
  conventions → NCC-05 encrypted locators).
- **Infrastructure adoption**: services refresh encrypted locators on
  address change — the example's `on ServiceRecord` handler is exactly that
  workflow, so a deployed instance publishes a locator for every record it
  accepts and refuses to use any it cannot read.

Scope notes and follow-ups: NIP-44 stays simulated under `nscript run` (the
simulator's envelope, not a real encryption — the guardrail that simulated
operations are labelled as such applies unchanged). Three language gaps this
stage ran into, none of them NCC-specific:

1. **Delivered content is always `Text`.** `event.content` for a delivered
   Locator arrives as the raw string the publisher sent, even though the
   event declares `EncryptedText`, so a reader holding the key still cannot
   call `nip44.decrypt_text` on it — it fails closed today. Plumb a content
   type (for example `content_type` on `CheckedEvent`) through event
   delivery so an `EncryptedText` field reaches the handler typed, and a
   reader can judge what it decrypted instead of what it cannot read.
2. **Operation calls inside a `publish` record's fields are never collected
   at check time**, so they never enter the capability policy and the
   handler aborts with `CapabilityDenied`. Bind the value to a `let` first
   (both the fixture and the example do); a fix belongs with the existing
   publish-field follow-up above.
3. **`.ns` string literals do not unescape**, so no JSON payload can be
   written as a literal — `ncc05.payload` builds it as a value instead,
   which is what §5.3 wants anyway.

## Stage 5 — NCC-06 service profile *(Done)*

A profile convention: no event kinds, no new host capability — every rule
it states is client policy over records stages 3 and 4 already ship. The
rules live in both places policy can live (open decision 2, resolved:
both), because the split is forced by the language: a script sees one
event at a time and keeps no store, so the cross-record half cannot be a
script at all.

- **Module** `modules/std/ncc06/0.1.0.nsm`, registered in `BUILTINS`, with
  `use ncc02`/`use ncc05`, the pinned `adad778` reference, no events and
  eight pure functions: `identity_reference`/`identity_key` read §Scope's
  identity reference (the hex pubkey a resolver searches records by; empty
  text for a URL that names a host or whose `npub` checksum fails — the
  reference itself is never dereferenced); `record_outranks` is §A's
  deterministic selection (usable beats unusable, then the greater
  freshness marker, then the lexicographically greatest event id) and
  `locator_marker` computes §A.2's marker (the payload's `updated_at`,
  else the record's `created_at`); `transport_rank` scores one URL into
  §E.1's tiers (`0` secure with `k`, `1` secure without, `2` onion — the
  family decides before the scheme — `3` insecure), `transport_order`
  stably regroups a list into those tiers keeping the payload's order
  within each, and `k_required` reports §E.2's verification obligation;
  `freshness_mode` renders §D's verdict, `fresh`, `stale` (inside the
  bounded window §D.3 requires to be surfaced) or `failed`.
- **Resolver** in `nscript-runtime`: `identity_reference_key`, a public
  `compute_event_id` (§A step 1 recomputes an id before its signature can
  mean anything), and `resolve_identity_reference` — query every concrete
  bootstrap relay for kinds 30059/30058 by the decoded pubkey (bounded by
  `RECORD_QUERY_LIMIT` × `RECORD_QUERY_BATCHES`), discard under §A step 1
  (author, kind, id recomputation, signature, duplicates), select under
  §A, walk §E.1 from the chosen locator's payload — never an identity
  reference — with the `u` fallback, and answer `IdentityResolution`
  (endpoint, source, §E.1 rank, `k`, `k_verified: false`, candidate and
  relay counts). Signature verification is injected as a callback, so the
  resolver itself stays free of host crypto and is testable against a
  scripted `SubscriptionHost`.
- **`deploy` integration**: `--relay` accepts identity references, which
  are partitioned out and never connected. The concrete relays stand in
  for the publication relay set (§C.2 — with none, deploy refuses at
  exit 2 before connecting anything), each identity is resolved before
  anything publishes, and the report prints the candidate count, the
  short ids of both selected records, the endpoint with its source and
  §E.1 rank, and the pinned `k` **with `verified: no`** — §E.2's TLS key
  pinning is not implemented, and a printed key must not imply one was
  checked. The resolved endpoint joins the pool; a failed resolution
  exits 1 with the reason, including the honest no-cache note that §D.3's
  stale fallback has nothing to fall back on.
- **Tests**: pure-function unit tests (§A's rule including unusable
  incumbents and id tie-breaks, §E.1's tiering table, §E.2, §D's three
  verdicts, §Scope decoding); resolver unit tests over a scripted relay
  (selection, endpoint ordering, the `u` fallback, `RelayUnavailable`,
  every error branch); and a `deploy_with_real_hosts` end-to-end test
  that answers the §C.2 query with real signed records and asserts the
  startup publish lands on the resolved endpoint, never the reference.
- **Fixtures**: `conformance/valid/ncc06-service-profile.ns` (a sidecar
  publishing its Service Record at startup and — on a relocate signal — a
  NIP-44-encrypted Locator, with readers judging both under the profile)
  and `conformance/invalid/ncc06-locator-marker-wrong-clock.ns`
  (`locator_marker(event.created_at, ...)` → `E1001`, the same clock
  inversion the NCC-02 and NCC-05 fixtures make).
- **Wire vector** `conformance/vectors/ncc06.json`, two entries in
  declaration order — the Service Record (kind 30059, `content: ""`) and
  the Locator (kind 30058, `content: null`) the fixture lowers — asserted
  against `inspect --json` by a CLI test.
- **Worked example** `examples/ncc06-service-monitor.ns`: a reader that
  rejects or tiers delivered Service Records (validity → §Scope guard →
  §E.1/§E.2 report) and renders §D's fresh/stale/failed verdict with §E.1
  ordering for Locators, run end to end by a CLI test.
- **Infrastructure adoption**: identity-first endpoint resolution — a
  deployed program is addressed (and `--relay`d) by identity reference,
  `deploy` resolves it through the publication relay set before anything
  publishes, and the monitor example is the reader half of the same
  workflow, judging every record it receives under the profile.
- **Docs**: spec subsection (Community conventions → NCC-06 service
  profile), matrix row, and `docs/DEPLOY.md`'s identity-reference
  section.

Scope notes and follow-ups: §A selection across several candidates and
§D.3's cached stale fallback cannot live in a script (one event per
handler, no store) — they live in `deploy`'s resolver, which by contrast
keeps no cache either, so no stale record is ever used there and the
error says so; `k` verification (§E.2) is unimplemented and reported as
`verified: no` everywhere the `k` is printed; and the checker reports
scalar↔scalar argument mismatches only, so a `List<Text>` passed where
`Text` expected is not flagged — the invalid fixture pins a scalar
mismatch for that reason. The fixture's top-level flow passes literals
to its operation calls because a top-level operation's arguments are
lowered statically (identifiers there read as `PubKey` names), which is
why the encrypted Locator publish sits in a handler like NCC-05's.

## Stage 6 — NCC-08 service identity rotation and handover *(Done)*

A multi-event state machine on top of the stage-3 anchor: continuity moves
only when a predecessor's proposal and the named successor's acceptance
both exist. The convention adds no authority transfer — it preserves
continuity between two identities without merging them — and it uses
regular, non-replaceable kind-1070 events because a completed handover is
historical evidence, not latest state.

- **Module** `modules/std/ncc08/0.1.0.nsm`, registered in `BUILTINS`, with
  `use ncc02`, the pinned `adad778` reference, one validator
  (`handover_role` accepts `predecessor` or `successor`) and one regular
  event `Handover` (kind 1070, `role`/`handover`/`service`/`p`/`e`/
  `effective`/`expires`/`reason`), plus twelve pure functions: `role`,
  `handover_id`, `service` and `counterparty` extract a delivered event's
  side, transition identifier, service and other identity;
  `proposal_is_valid(tags, created_at)` requires §8.1's shape and refuses a
  backdated `effective`; `acceptance_is_valid(tags)` requires §9.1's shape;
  `pair_is_valid(...)` checks §10 across both events — authors, tags, the
  exact proposal reference (`EventId`), shared identifiers, order and the
  `expires` window — from values the caller supplies;
  `effective_time(has_effective, effective, acceptance_created_at)` renders
  §11's moment; `state(accepted, effective_at, now)` answers
  proposed/accepted/effective; and `conflicts_with(...)`, `continues(...)`
  and `chain_has_loop(chain)` are §15's ambiguity, §14's link and §14's
  loop, all as pure data with no clock read inside a host.
- **Runtime** dispatch in `nscript-runtime`'s shared pure-function registry
  beside the other NCC modules, with a unit test covering extraction,
  proposal/acceptance/pair validation (including wrong successor, wrong
  predecessor, wrong reference, mismatched identifiers, ordering, expiry
  and malformed timestamps), effective time, the three states, conflicts,
  chain links, loop detection and wrong argument shapes.
- **Fixtures**: `conformance/valid/ncc08-handover.ns` (a predecessor
  publishing its proposal and readers judging delivered proposals and
  acceptances, each half on its own) and
  `conformance/invalid/ncc08-proposal-wrong-clock.ns`
  (`proposal_is_valid(event.tags, event.content)` → `E1001`, the scalar
  clock inversion the other NCC fixtures make).
- **Wire vector** `conformance/vectors/ncc08.json`: the predecessor
  proposal's kind 1070 and `role`/`handover`/`service`/`p`/`effective`/
  `expires`/`reason` tags, asserted against `inspect --json`.
- **Worked example** `examples/ncc08-rotation-bot.ns`: the successor side
  of the workflow — it validates a predecessor's proposal for its service
  and publishes the matching acceptance (real predecessor pubkey from the
  event author, exact proposal id as `e`), and reports acceptances it
  receives, run end to end by a CLI test.
- **Docs**: spec subsection (Community conventions → NCC-08 service
  identity rotation) and matrix row.

Scope notes and follow-ups: §10's pair check and §14's chain walk span two
or more events, and a handler sees one event at a time with no store, so
they are pure functions over caller-supplied values rather than host
state — the successor example completes a handover from one delivered
event, and the pair/chain functions are unit-tested and documented for a
client that holds both halves. Signatures stay the host's business (§10.2),
not a module check. And publish-field types are not nominally checked: the
successor example publishes `p: event.author` (a `PubKey`) into a field the
event declares `Text`, and it lowers to the hex tag correctly because only
module function-call arguments are type-checked — the same checker gap the
NCC-06 invalid fixture worked around.

## Stage 8 — NCC-09 scoped operator authority *(Done)*

The first delegated-authority convention, and the first stage written
against the bumped `adad778` pin. A principal grants an operator named
scopes for one service; the operator stays its own identity and the
convention defines the container, not what a scope means.

- **Module** `modules/std/ncc09/0.1.0.nsm`, registered in `BUILTINS`, with
  `use ncc02`, the `adad778` reference, a `grant_status` validator and the
  addressable `AuthorityGrant` event (kind 30064: `d`, `service`, `p`,
  `status`, `scope` list, `expiration`, `valid_from`, `note`), plus ten
  pure functions: `operator`/`service`/`status`/`scopes` extract;
  `address(service, operator)` builds the `<service>:<operator>` `d`;
  `scope_namespace`/`scope_is_valid` classify §8's `ncc:`/`pubkey:` forms
  and leave everything else opaque; `grant_starts_at(tags, created_at)`
  renders §6.4's start; `grant_is_valid(tags, now)` is §13's validity
  (active, one operator, a service, inside the window, malformed fails
  closed); and `authorises(tags, scope, now)` is §12's authority check.
- **Runtime** dispatch with a unit test covering extraction, the two scope
  namespaces, §6.4's start, the window boundaries (past `expiration`,
  before `valid_from`, revoked, two operators, malformed timestamps) and
  the scope test.
- **Fixtures**: `conformance/valid/ncc09-authority-grant.ns` (a principal
  publishing a scoped, time-bounded grant and readers judging delivered
  grants) and `conformance/invalid/ncc09-grant-wrong-clock.ns`
  (`grant_is_valid(event.tags, event.content)` → `E1001`).
- **Wire vector** `conformance/vectors/ncc09.json` (kind 30064 with `d`,
  `service`, `p`, `status`, `scope`, `valid_from`, `expiration`, `note`).
- **Worked example** `examples/ncc09-operator-grant-bot.ns`: the principal
  publishes the grant and reports a received grant's side, start, scopes
  and whether `ncc:10:publish` is delegated, run end to end by a CLI test.
- **Docs**: spec subsection and matrix row.

## Stage 9 — NCC-10 service operational state *(Done)*

Current operational state over the service identity, published by the
service directly or by an NCC-09 operator. This is the stage that needed
the multi-column tag infrastructure: an operator state names its principal
in a three-column `operator_for`.

- **Module** `modules/std/ncc10/0.1.0.nsm`, registered in `BUILTINS`, with
  `use ncc02`/`use ncc09`, a `state_value` validator and the addressable
  `ServiceState` event (kind 30065: `d`, `service`, `state`, `since`,
  `expected_until`, `incident`, `successor`, `operator_for`), plus eight
  pure functions: `state`/`state_service` extract,
  `state_is_recognised` checks §4's five values, `is_direct` separates a
  service state from an operator's, `principal`/`operator_service` read
  the two columns of `operator_for` (its name avoids colliding with the
  `ncc09.service` export scripts load together), and
  `operator_for_tag`/`operator_address` build the three-column tag value
  and the `<pubkey>:<service>` `d`.
- **Runtime** dispatch with a unit test covering extraction, recognition,
  direct-versus-operator, the builder's two columns and the address.
- **Fixtures**: `conformance/valid/ncc10-service-state.ns` (a direct
  `maintenance` state with `since`/`expected_until`/`incident`, and
  readers that report direct and operator states) and
  `conformance/invalid/ncc10-state-wrong-type.ns`
  (`state_is_recognised(event.created_at)` → `E1001`).
- **Wire vector** `conformance/vectors/ncc10.json` (kind 30065 direct
  state).
- **Worked example** `examples/ncc10-status-bot.ns`: an authorised
  operator publishes a three-column `operator_for` state under a principal
  it does not impersonate and reports the states it sees, run end to end
  by a CLI test.
- **Docs**: spec subsection and matrix row.

## Stage 10 — NCC-11 portable trust policy *(Done)*

Policy data over the whole stack: a named, addressable document of
namespaced rules and trusted certifiers that a client or agent applies to
its own decisions. Its `rule` and `trust certifier` tags are three-column,
so it stands on the same infrastructure as stage 9.

- **Module** `modules/std/ncc11/0.1.0.nsm`, registered in `BUILTINS`, with
  `use ncc02`/`use ncc05`, a `present` validator and the addressable
  `TrustPolicy` event (kind 30067: `d`, `rule` list, `trust` list, free
  `content`), plus nine pure functions: `policy_id`; `rule_keys`,
  `rule_value` (contradictory duplicates answer empty, §23),
  `rule_value_is` and `certifiers` read the three-column tags;
  `rule_is_known` and `rule_value_is_valid` encode §9's rules and their
  allowed values while leaving unknown keys opaque (§24); and `rule` and
  `certifier` build the two three-column tag values.
- **Runtime** dispatch with a unit test covering the builders' columns,
  rule extraction, conflict handling, certifiers, recognition and value
  validation (including the structured `max-stale-age` and
  `transport:<scheme>` shapes).
- **Fixtures**: `conformance/valid/ncc11-trust-policy.ns` (a client that
  publishes a policy from a handler — a `.ns` literal cannot carry the tag
  column separator, so the rules are built by the module — and reads a
  delivered policy's rules and certifiers) and
  `conformance/invalid/ncc11-rule-value-wrong-type.ns`
  (`rule_value(event.tags, event.created_at)` → `E1001`).
- **Wire vector** `conformance/vectors/ncc11.json` (kind 30067; the
  checked snapshot carries the literal `d`, since the rules are computed).
- **Worked example** `examples/ncc11-policy-client.ns`: a client
  publishing a policy and evaluating a received one, run end to end by a
  CLI test.
- **Deploy end to end**: `deploy_publishes_three_column_policy_tags` runs
  the real relay path — through a real NIP-46 signer — and asserts the
  exact three-column `rule` and `trust certifier` wire tags, the coverage
  the checked vector cannot give.
- **Docs**: spec subsection and matrix row. This is also where Stage 5's
  two printed-but-unimplemented gaps (NCC-06 §E.2 key pinning and §D.3
  stale fallback) gain a data home: `ncc:02:key-pinning` and
  `ncc:05:stale-fallback` are the policy keys a client would enforce, while
  the host still performs neither.

## Stage 11 — NCC-13 software package release profile *(Done)*

A profile with no event of its own: every rule adds tags to a NIP-51
Release Artifact Set and the NIP-94 artefacts it references (§2), so this
stage's only new event is a minimal `ArtefactMetadata` declaration for
NIP-94's kind 1063 carrying NCC-13's own `os`/`arch`/`format` selectors —
file identity, hash and location stay NIP-94's, undeclared here. Software
Application (32267) and Git Repository (30617) stay address text a script
builds and compares; NCC-13 does not define their identity either (§3).

- **Module** `modules/std/ncc13/0.1.0.nsm`, registered in `BUILTINS`, with
  `use ncc09`, the pinned `186c3ad` reference, a `present` validator, the
  addressable `ReleaseArtifactSet` event (kind 30063: `d`, `a`, `version`,
  `version_scheme`, `channel`, `source`, `commit`, repeatable `requires`,
  `optional`, `conflicts`, `e`, and `operator_for`), the regular
  `ArtefactMetadata` event (kind 1063: NIP-94's `url`/`x`/`m`/`size` plus
  NCC-13's `os`/`arch`/`format`), and twenty-two pure functions:
  `application`/`version`/`source`/`commit` extract their tags directly;
  `version_scheme` and `channel` apply §8.4/§9.1's defaults
  (`"opaque"`/`"stable"`) when the tag is absent, so an unscoped version is
  never assumed ordered; `requirement` builds the two-column
  `requires`/`optional`/`conflicts` value (mirroring NCC-10's
  `operator_for` shape) and `requirement_address`/`requirement_constraint`
  split it back, while `requires`/`optional_dependencies`/`conflicts` read
  every repeated entry, in order, for the caller to AND-fold (§13);
  `release_operator_for`/`release_operator_project`/
  `release_operator_application` build and read the `ncc:13:publish`
  operator claim (§33) — named distinctly from NCC-10's
  `operator_for_tag`, since importing both modules in one program
  requires every declared name across them to be unique (a real
  collision found composing the two in `examples/service-operator-bot.ns`);
  `semver_is_valid` and
  `semver_compare` implement SemVer §11 precedence (major/minor/patch,
  build metadata parsed and discarded, prerelease ranked below the release
  it precedes, prerelease identifiers compared per §11.4); and
  `version_satisfies` judges one `=`/`>`/`>=`/`<`/`<=` constraint —
  equality under any scheme, a relational operator only under `semver`,
  matching §8.2/§8.3's refusal to generically order CalVer or opaque
  versions. `artefact_os`/`artefact_arch`/`artefact_format` extract the
  NIP-94 selectors and `artefact_matches` judges §19–20's `os`/`arch` match
  with `"any"` as the platform-independent wildcard on either side; package
  format (§19 step 3) stays the caller's own policy membership check, not
  an equality this function can decide.
- **Runtime** dispatch in `nscript-runtime`'s shared pure-function
  registry, with a unit test covering extraction and the two defaults, the
  two-column requirement and operator_for builders and readers, SemVer
  validity, precedence (including the prerelease-before-release rule and
  identifier comparison), constraint satisfaction under both semver and a
  non-ordered scheme, and artefact matching including the `any` wildcard.
- **Fixtures**: `conformance/valid/ncc13-package-release.ns` (a handler
  publishes a release with `requires`/`conflicts` built by
  `ncc13.requirement` — a `.ns` literal cannot carry the tag column
  separator — then judges delivered releases for upgrade eligibility and
  reads a delivered artefact's platform match) and
  `conformance/invalid/ncc13-version-satisfies-wrong-type.ns`
  (`version_satisfies(scheme, version, event.created_at)` → `E1001`, since
  a constraint is Text, never a timestamp).
- **Wire vector** `conformance/vectors/ncc13.json` (kind 30063; the checked
  snapshot holds the literal `d`/`a`/`version`/`version_scheme`/`channel`/
  `source`/`commit`, since `requires`/`conflicts` are computed), asserted
  against the `inspect --json` publication trace, plus two `nscript run`
  tests exercising the `ReleaseArtifactSet` and `ArtefactMetadata` handlers
  with real two-column tags.
- **Worked example** `examples/ncc13-release-monitor.ns`: publishes a
  release for one Software Application, judges every Release Artifact Set
  it receives against a tracked installed version and preferred channel
  (§26–28), and selects a matching artefact by platform. Run end to end by
  a CLI test covering the beta-declined, stable-accepted, mismatched- and
  matched-artefact paths.
- **Docs**: spec subsection and matrix row.
- **Infrastructure adoption**: a package-distribution bot publishes its own
  releases and a monitor decides upgrade eligibility, dependency and
  conflict exposure, and artefact selection purely from published Nostr
  events — exactly `examples/ncc13-release-monitor.ns`'s workflow.

Scope notes: NCC-13 v0.1 deliberately excludes ranges, wildcards and
boolean dependency expressions (§13); `version_satisfies` matches that
scope rather than a general SemVer range library. Dependency resolution
(§14) and installation itself are explicitly out of NCC-13's scope and
are not implemented here.

## Guardrails

- No NCC-specific syntax: conventions arrive as typed modules with records,
  validators, events, and operations.
- No ambient authority: trust stores, override modes, stale fallback, and
  transport preference are script-visible data; time flows from `clock` into
  pure functions; encryption and signing stay behind existing capabilities.
- No overclaiming: simulated module operations are labelled as such in docs;
  only lowered publish paths claim wire-real behaviour.
- NCC endorsements and succession records are adoption signals and must not
  feed permission or trust decisions implicitly.

## Open decision points

1. NCC-03: fix the upstream kind model, or stay deferred (blocks stage 7 only).
2. ~~Stage 5: identity-reference resolution inside `deploy`, or script-level
   resolution only~~ *(resolved at stage 5: both — §A selection, the §E.1
   walk and §C.2 querying live in `deploy`'s resolver, because a script
   sees one event at a time and keeps no store; §Scope, §E.1/E.2 tiering
   and §D verdicts stay script-visible as `ncc06` pure functions.)*
3. ~~NCC-09/10/11 (added upstream after the pin): review and schedule as
   post-Draft-0.1 stages with a pin bump, or defer until a workflow needs
   them — none of their text exists at `fe5981f`, so lowering any of them
   changes the pin the release records.~~ *(resolved at stages 8–10: all
   three implemented against the bumped `adad778` pin, with the
   multi-column tag infrastructure they required in place. The release now
   records `adad778`.)*
4. ~~NCC-13 (added upstream after the `adad778` pin): schedule as a further
   stage with another pin bump, or defer.~~ *(resolved at stage 11: the pin
   moved to `186c3ad` and NCC-13 shipped on the multi-column tag
   infrastructure stages 8–10 already built — no further infrastructure
   was needed.)*
