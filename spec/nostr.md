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
