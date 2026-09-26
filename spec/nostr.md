# Nostr interoperability

Status: **Draft 0.1 — normative**

NScript adds source-level safety while emitting and consuming standard Nostr
protocol data. Implementations MUST NOT require NScript-specific relay support.

## NIP-01

`nip01` defines `Event`, `Unsigned<E>`, `Signed<E>`, `Filter<E>`, relay request
and response errors, and standard event fields. Event serialisation uses the
canonical NIP-01 array for ID calculation, lowercase hexadecimal fields, and
standard JSON relay messages.

Incoming events are exposed only after structural validation, ID recomputation,
signature verification, and event-type validation. Invalid events produce
metrics or diagnostics but never enter user handlers.

Query lowering maps:

| NScript predicate | NIP-01 filter |
| --- | --- |
| `event.id == x` | `ids: [x]` |
| `author == x` | `authors: [x]` |
| event type | `kinds: [kind]` |
| `tags.x contains y` | `#x: [y]` |
| `since t` / `until t` | `since` / `until` |
| `limit n` | `limit` |

Equality alternatives on the same field may share one filter. `or` generally
becomes multiple filters within one `REQ`. A conjunction that cannot fit one
filter requires separate bounded requests followed by local intersection; it
must not be represented as multiple filters in one `REQ`. Implementations apply
the language specification's bounding rule before local evaluation.

## Typed tags

The starter module defines:

| Source value | Wire tag |
| --- | --- |
| `Person(pubkey, relay?)` | `["p", hex-pubkey, relay?]` |
| `EventRef(id, relay?, author?)` | `["e", hex-id, relay?, author?]` |
| `Root(id, relay?, author?)` | `["e", hex-id, relay-or-empty, "root", author?]` |
| `ReplyTo(id, relay?, author?)` | `["e", hex-id, relay-or-empty, "reply", author?]` |
| `Quote(target, relay?, author?)` | `["q", hex-id-or-address, relay-or-empty, author?]` |
| `AddressRef(addr, relay?)` | `["a", coordinate, relay-or-empty]` |
| `Identifier(text)` | `["d", text]` |
| `Topic(text)` | `["t", text]` |

`Person` and `EventRef` originate in NIP-01; `Root` and `ReplyTo` follow NIP-10;
and `Quote` follows the NIP-10/NIP-18 quote convention. Module-specific
validation may further constrain these values. Serialization preserves source
order except where a NIP requires canonical ordering.

## NIP-19

`nip19` provides checked constructors and conversions for `Npub`, `Nsec`,
`NoteId`, `Nprofile`, `Nevent`, and `Naddr`. Decoding validates Bech32 checksums,
required TLVs, lengths, and known singleton cardinality. Unknown TLVs are
ignored semantically as required by NIP-19 and preserved when a value is
round-tripped without modification. Encoded identifiers are limited to 5,000
characters. Conversion to `PubKey`, `SecretKey`, `EventId`, or an event
coordinate is explicit and fallible when the identifier lacks the needed data;
secret conversion additionally requires the high-risk capability.

## NIP-46

`nip46()` provisions a signer handle through the host. The runtime, rather than
the script, owns bunker connection details, its disposable client key, and
authorization state. It tracks the remote-signer pubkey separately from the user
pubkey returned by `get_public_key`. Signing passes canonical unsigned event data
through `sign_event` and returns a signed event only after local ID, signature,
and user-pubkey validation. NIP-46 transport encryption follows NIP-44.

Every signing request is checked against both the static program permission and
the signer's own policy. Either may deny it. A NIP-46 timeout or disconnect is
recoverable and MUST NOT silently fall back to a local secret key.

## Replacement semantics

`latest E` selects the valid event with the greatest `created_at` under Nostr
replacement rules for the event type and author. Equal timestamps select the
lexicographically lowest event ID. Parameterised types also include the decoded
`d` identifier in their coordinate. Deletion or relay absence does not prove
global deletion; APIs expose the observed relay set with resolved results.

## Module extension contract

A declarative `.nsm` NIP module declares:

- its name, semantic version, and compatible language range;
- exported types, events, tags, functions, and errors;
- validation and wire lowering rules;
- effects and permissions required by host functions; and
- conformance vectors.

Modules are signed release artifacts in the package system. The compiler treats
their declarations as ordinary typed interfaces; it MUST NOT special-case a NIP
other than the bootstrap needed to load the standard modules.

Module schemas contain no executable native or WASM plugins. Their constrained
validation and lowering expressions are defined in the module specification.

## Community conventions

Nostr Community Conventions (NCCs) are shared usage patterns of existing
primitives, published by the convention repository pinned in the specification
README. They are implemented as ordinary modules under the `ncc` namespace
(`ncc00`, `ncc02`, `ncc07`, ...) using the same records, validators, events,
tags, and host operations as NIP modules.

A community-convention module:

- declares each convention event with its fixed kind, storage mode, content
  encoding, and allowed tag union, so `publish` statements lower fields to wire
  tags through the ordinary publication path;
- validates convention rules that depend on wall time through pure functions
  that receive `now` from the caller, never by reading the clock inside a
  validator;
- keeps trust policy — attestation stores, override modes, stale fallback,
  transport preference — in script-visible data rather than in host behaviour;
- treats endorsements and succession records as adoption signals that never
  grant permissions or satisfy capability checks.

Extensions MUST NOT change the meaning of conforming source when a convention
module is absent: conventions are ignorable by default, and no NIP or language
keyword depends on them.

### NCC-00 document lifecycle

`ncc00` implements the document-lifecycle convention: an NCC is an
addressable event of kind 30050 addressed by an `ncc-XX` identifier in its
`d` tag, carrying required `title`, `published_at`, and `status` tags whose
value is one of `draft`, `published`, `superseded`, `withdrawn` (§A.5).
Steward handover is a kind-30051 succession record whose required
`authoritative=event:<id>` reference names the document the current steward
recognises; adoption is a kind-30052 endorsement whose required
`endorses=event:<id>` reference names the document being supported;
supporting material — guides, implementation notes, FAQs — is a kind-30053
supporting document addressed by its own per-author `d` and pinned to an NCC
with `for=ncc-XX`. A `publish NccDocument` (or succession, endorsement, or
supporting-document) statement lowers its fields to wire tags through the
ordinary publication path, so the lifecycle reaches relays as standard
NIP-01 addressable data and each address keeps only the author's latest
revision.

Lifecycle rules are exposed as pure functions whose time comes from the
caller: `ncc00.identifier(event.tags)` and `ncc00.status(event.tags)`
extract the addressed identifier and status from the handler-side
`name=value` rendering of an event's tags; `ncc00.identifier_is_valid(id)`
checks the `ncc-` prefix against the digits that must complete it, and
`ncc00.status_is_valid(status)` checks §A.5's four values;
`ncc00.succession_is_effective(event.tags, now)` reports whether a
succession record is in force at the caller's `now` — a record with no
`effective_at` is in force from authoring, one whose `effective_at` has
arrived is in force, and a malformed `effective_at` never reads as
effective; `ncc00.authority_label(steward_acknowledged)` renders Appendix
B's resolution labels, `Steward-acknowledged` and `De-facto (adopted)`.
Scripts hold no wall clock (spec/language.md §9), so `published_at` and
`now` flow from a delivered event's `created_at` or another caller-held
timestamp.

NScript publishes no kind-30050 convention document of its own: doing so
would claim stewardship of a convention it does not author. Its record of
which NCC revisions it implements ships instead as authority-free kind-30053
supporting documents — Appendix E is explicit that supporting documents
confer no authority — published by
`examples/ncc00-implementation-ledger.ns`. Succession and endorsement
records remain adoption signals: they never grant permissions or satisfy
capability checks, and `ncc00.authority_label` is display guidance, not a
trust decision.

### NCC-02 endpoint identity binding

`ncc02` implements the pubkey-owned service-discovery convention: a Service
Record is an addressable event of kind 30059 addressed by its `d` service
identifier, carrying the required `u` endpoint URI, `k` transport-key
fingerprint, and `exp` expiry tags; an optional Certificate Attestation of
kind 30060 is addressed by `d=<srv>:<subj>` and carries required `subj`,
`srv`, `e`, `std`, `lvl` (one of §2's `self`, `verified`, `hardened`),
`nbf`, and `exp` tags; a Revocation of kind 30061 is addressed by the
revoked attestation's event id and names it again in its required `e` tag.
A `publish ServiceRecord` (or CertificateAttestation, or Revocation)
statement lowers its fields to wire tags through the ordinary publication
path, so each record reaches relays as standard NIP-01 addressable data and
each address keeps only the latest revision: a fresh attestation replaces a
stale one for the same service and subject while different pairs stay
independent, and every revocation stays independently addressable.

Trust rules are exposed as pure functions whose time comes from the caller.
`ncc02.service_id(event.tags)`, `ncc02.endpoint(event.tags)`,
`ncc02.transport_key(event.tags)`, and `ncc02.trust_level(event.tags)`
extract the convention's fields from the handler-side `name=value` rendering
of an event's tags, and `ncc02.endpoint_scheme(endpoint)` classifies an
endpoint's lowercased scheme, returning empty text for one carrying no
well-formed `scheme://` prefix;
`ncc02.record_is_valid(event.tags, now)` reports whether a record still
carries its required `d` and `k` and an `exp` that has not passed at the
caller's `now` — `u` deliberately is not required, so a private or
invite-only service keeps the record as its identity anchor while NCC-05
resolves reachability; `ncc02.attestation_is_valid(event.tags, now)` also
requires every attestation tag, the `<srv>:<subj>` scoping of `d`, a known
trust level, and `nbf <= now < exp`; and
`ncc02.revocation_is_for(event.tags, attestation_id)` reports whether a
revocation's `e` names that attestation, which withdraws it whatever its
own `exp` says (§3, revocation overrides expiry). Which certifiers and
levels a client accepts stays script-visible trust policy, the trust model
stays closer to SSH `known_hosts` than to web PKI, and reading a record or
an attestation never grants permissions or satisfies capability checks.
Connecting to the endpoint and comparing the observed transport key against
`k` remains the client's own verification — the record asserts the binding
rather than performing it — and scripts hold no wall clock
(spec/language.md §9), so `now` flows from a delivered event's `created_at`
or another caller-held timestamp, as `examples/ncc02-service-registry.ns`
does while publishing its own record and judging the ones it receives.

### NCC-07 capability manifests

`ncc07` implements the capability-manifest convention: a service advertises
what it can do as an addressable event of kind 30062 addressed by the literal
`d` tag `capabilities`, carrying repeatable `cap` tags whose values are
capability identifiers. A `publish CapabilityManifest` statement lowers its
`d` and `cap` fields through the ordinary publication path — `cap` repeats the
tag once per list element — so the manifest reaches relays as standard NIP-01
addressable data and is replaced by later revisions under the same address.
The manifest is an advertisement: NCC-07 §4 is explicit that publishing one
says nothing about which NIPs the publisher actually implements, and reading a
peer's manifest MUST NOT by itself grant permissions or satisfy capability
checks.

Selection over a received manifest is exposed as pure functions that take no
clock: `ncc07.capabilities(event.tags)` extracts the advertised identifiers
from the handler-side `name=value` rendering of the event's tags,
`ncc07.supports(advertised, wanted)` tests membership by exact string
comparison, `ncc07.capability_namespace(id)` classifies an identifier as
`nip`, `ncc`, `pubkey`, or `opaque` for one of the convention's three
namespaces (§7), and `ncc07.capability_is_valid(id)` checks that a known
namespace prefix is completed rather than malformed. Identifiers outside the
three namespaces are opaque strings; consumers MUST treat unknown capability
identifiers as opaque and ignorable (§7). Resolution of competing manifests
uses standard addressable replacement — greatest `created_at`, then lowest
event ID — and adds no new selection rules.
