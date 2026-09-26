# NCC integration plan

This plan records how Nostr Community Conventions from
[`imattau/nostr-community-conventions`](https://github.com/imattau/nostr-community-conventions)
are incorporated into NScript. It follows the design intents in `README.md`
(nominal typing, explicit capabilities, declared permissions, lowering to
existing protocols) and the workflow-first rule in `ROADMAP.md` (no protocol
breadth without a concrete workflow and conformance need).

The NCC repository is pinned at commit
`fe5981fd83becb0de53386569ede5604ae2ca7ef`. A release MUST record a new pin
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
2. Stage 5: identity-reference resolution inside `deploy`, or script-level
   resolution only (decide at stage 5).
