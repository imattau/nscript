# NCC integration plan

This plan records how Nostr Community Conventions from
[`imattau/nostr-community-conventions`](https://github.com/imattau/nostr-community-conventions)
are incorporated into NScript. It follows the design intents in `README.md`
(nominal typing, explicit capabilities, declared permissions, lowering to
existing protocols) and the workflow-first rule in `ROADMAP.md` (no protocol
breadth without a concrete workflow and conformance need).

The NCC repository is pinned at commit
`712385839c5cd9d254c765b1fa900d0670a468dc`. A release MUST record a new pin
when NCC lowering behaviour changes, mirroring the NIP review-commit rule in
[`spec/README.md`](spec/README.md).

## Reviewed conventions

| NCC | Kinds | Depends on | Core surface |
| --- | --- | --- | --- |
| 00 | 30050 doc, 30051 succession, 30052 endorsement, 30053 supporting doc | — | Meta-convention: publishing and revising NCC documents on Nostr |
| 02 | 30059 service record, 30060 attestation, 30061 revocation | — | Endpoint identity binding (`u`/`k`/`exp`) and optional attestation trust |
| 03 | definition kind unresolved, roll 30000, audit 36999 | — | Elections, votes, one vote per pubkey, voting window |
| 05 | 30058 locator | 02 (anchored mode) | Encrypted `ip:port` locators, TTL freshness, endpoint ordering |
| 06 | none (behaviour only) | 02 + 05 | Client/sidecar conflict, caching, and transport policy |
| 07 | 30062 manifest | composes 02/05 | `d=capabilities` with repeatable `cap` tags |
| 08 | 1070 proposal + acceptance | 02 (service scope) | Two-event identity handover with chains and conflict rules |

## Upstream prerequisites

These are defects in the NCC repository itself and must be fixed (or the
convention deferred) before implementation here:

1. **NCC-02 kinds 30060 and 30061 declare no `d` tag** while sitting in the
   30000–39999 addressable range. Without `d`, every attestation and
   revocation from one certifier replaces every other at `d=""`. Fix: require
   `d` (suggested: `srv` for 30060, the revoked event id for 30061).
2. **NCC-03's kind model is unresolved**: the Election Definition kind is not
   normatively stated, §5.1 says "non-replaceable" while the companion library
   emits kind 36998 (addressable range), vote replaceability is a MAY, and the
   electoral roll's kind 30000 overlaps NIP-51 legacy list space. NCC-03 is
   deferred in `ROADMAP.md` until this is resolved.

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
| 7 | NCC-03 | Largest and least resolved; blocked on the upstream fix | Builds on `poll-tally-bot.ns` and Concord governance |

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
3. Stage 2: whether NScript itself publishes its own extension documents as
   kind-30050 events, or only exposes the module to user scripts.
