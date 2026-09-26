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
