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
(`ncc00`, `ncc02`, `ncc05`, `ncc06`, `ncc07`, `ncc08`, `ncc09`, `ncc10`, `ncc11`, ...) using the same records, validators, events,
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

### NCC-05 encrypted locators

`ncc05` implements the encrypted-reachability convention: a Locator is an
addressable event of kind 30058 addressed by its required `d` destination
identifier, carrying the optional `expiration` tag of Unix seconds and the
optional `private` tag, whose `content` is an encrypted payload document
rather than public text. NCC-05 §5.1 requires that content be encrypted: a
`publish Locator` statement lowers its `d` and `expiration` fields to wire
tags through the ordinary publication path while `content` carries the
NIP-44 envelope whole — `nip44.encrypt_text`'s result lowers straight into
the event's content — so the record reaches relays as standard NIP-01
addressable data, replaced by later revisions under the same address, while
the payload stays unreadable to anyone without the key. §5.2's single
exception, a locator whose destination is already public, is the only
payload permitted in the clear.

What is encrypted is the §5.3 payload document, and pure functions build it
rather than string assembly: `ncc05.payload(ttl, updated_at, endpoints,
caps)` renders `{v, ttl, updated_at, endpoints, caps}`, omitting `caps` when
it is empty and refusing (with empty text) a non-positive `ttl` or an
endpoint that does not parse as §5.4 demands;
`ncc05.endpoint_object(url, priority, family, k)` renders one §5.4 endpoint,
leaving `family` and `k` out when they are empty and rendering no endpoint
at all for an empty `url`; `ncc05.endpoint_family(url)` classifies a
destination as `onion`, `ipv6`, or `ipv4` — empty text when the URL's own
spelling does not decide it, since guessing would move the endpoint in §7's
selection order; and `ncc05.payload_endpoints(payload)` and
`ncc05.payload_caps(payload)` read the arrays back out of any payload a
reader was handed, ordered into §7's attempt order of ascending `priority`
(§5.4's default of 1000 when a payload omits it), then `onion`, `ipv6`,
`ipv4`, then the URL itself.

Freshness follows the same time-from-the-caller rule as every other
convention validator: `ncc05.payload_is_fresh(payload, now)` reports
`now <= updated_at + ttl`, and `ncc05.record_is_fresh(event.tags,
event.content, now)` requires the `d` tag, a payload that is itself fresh at
`now`, and — where the record carries one — an `expiration` tag that has not
passed, so a Locator is judged against the earlier of its payload window and
its tag (§8). `ncc05.locator_name(event.tags)` extracts the destination a
reader is addressed by.

Scripts hold no wall clock (spec/language.md §9), so `now` flows from a
delivered event's `created_at` or another caller-held timestamp, and who may
decrypt a peer's locator stays script-visible policy (§9): a reader that
cannot decrypt a §5.1 envelope discards it rather than using what it cannot
read, and reading a Locator never grants permissions or satisfies capability
checks, as `examples/ncc05-locator-bot.ns` does while publishing its own
locator and judging the ones it receives.

### NCC-06 service profile

`ncc06` implements the service-profile convention, which adds no event kinds
of its own: NCC-06 profiles how a client reads the NCC-02 Service Record and
NCC-05 Locator a service publishes — which of several candidate records wins
(§A), what a URL that names a key rather than a host means (§Scope), how
endpoints are tiered (§E.1), when a transport must present the pinned key
(§E.2), and when a record may still be used past its window (§D) — all as
pure functions over values a script already holds.

An identity reference — an `npub` authority in whatever scheme surrounds it
— is never dereferenced: `ncc06.identity_reference(url)` reports one, and
`ncc06.identity_key(url)` decodes the hex pubkey that authority names
(empty text for a URL that names a host or whose checksum fails), the key a
resolver searches records by (§Scope). §A's deterministic selection over
several candidates is exposed as `ncc06.record_outranks(a_usable, a_marker,
a_id, b_usable, b_marker, b_id)` — usable beats unusable, then the greater
freshness marker, then the lexicographically greatest event id, so two
relays holding the same candidates settle on the same record — with
`ncc06.locator_marker(payload, created_at)` computing a Locator's §A.2
marker (the payload's `updated_at`, else the record's `created_at`).

Transport policy stays script-visible: `ncc06.transport_rank(url, k)` scores
one endpoint into §E.1's tiers — `0` secure with `k` in hand, `1` secure
without, `2` onion (the family decides before the scheme does), `3` insecure
or unrecognised — and `ncc06.transport_order(endpoints, k)` stably regroups a
list into those tiers, keeping the payload's order within each so a
first-successful-connection walk starts from the most trusted tier;
`ncc06.k_required(url)` reports whether §E.2 expects key material to match
the NCC-02 `k` for that transport. §D's verdict on what may be used right
now comes from `ncc06.freshness_mode(has_fresh, record_age, max_staleness)`,
which answers `fresh`, `stale` (inside the bounded staleness window, whose
use §D.3 requires to be surfaced), or `failed`.

Scripts hold no wall clock (spec/language.md §9), so `now` flows from a
delivered event's `created_at` or another caller-held timestamp. A handler
sees one event at a time and keeps no store, so §A's cross-record selection
and §D.3's cached fallback have no home in a script; `nscript deploy`
resolves an identity-reference `--relay` under the profile in its own
resolver instead: it queries the concrete relays standing in for a
publication relay set (§C.2), selects under §A, walks §E.1 to a concrete
endpoint, and prints what it selected — including the `k` it did not
verify, since TLS key pinning is not implemented and a printed key must not
imply one. `examples/ncc06-service-monitor.ns` judges the records it
receives the same way, one event at a time.

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

### NCC-08 service identity rotation

`ncc08` implements the identity-handover convention: a service moves from
one pubkey to another through a mutually acknowledged pair of regular,
non-replaceable kind-1070 events, told apart by a `role` tag — a
predecessor-signed proposal (`role=predecessor`, naming exactly one
successor `p`) and a successor-signed acceptance (`role=successor`,
naming exactly one predecessor `p` and the exact proposal `e`). A
`handover` identifier binds the two halves and a `service` identifier
scopes what transfers. A `publish Handover` statement lowers its fields to
wire tags through the ordinary publication path, so each half reaches
relays as standard NIP-01 data — and, being regular events rather than
addressable ones, both stay historical evidence instead of being replaced
by the author's next revision.

Validation is exposed as pure functions. `ncc08.role(event.tags)`,
`ncc08.handover_id(event.tags)`, `ncc08.service(event.tags)` and
`ncc08.counterparty(event.tags)` extract the side, the transition
identifier, the service, and the other identity the `role` addresses;
`ncc08.proposal_is_valid(event.tags, created_at)` requires §8.1's shape and
refuses a proposal whose `effective` predates it; and
`ncc08.acceptance_is_valid(event.tags)` requires §9.1's shape.
`ncc08.pair_is_valid(...)` is §10 over both events at once — the caller
passes each side's author, tags, id and `created_at`, so the mutual
acknowledgement is checked against real authorship, the exact proposal
reference, the shared identifiers, and the proposal's `expires` window.
Signatures remain the host's business, never the module's.

Time and state are pure too. `ncc08.effective_time(has_effective,
effective, acceptance_created_at)` renders §11's effective moment — the
proposal's `effective` when it carried one, else the acceptance's own
time — and `ncc08.state(accepted, effective_at, now)` answers `proposed`,
`accepted` or `effective`: a proposal alone is never accepted, and an
accepted pair becomes effective only once `now` reaches that moment, with
the predecessor still current until then. Chain and conflict rules are
data, not state: `ncc08.continues(service, successor, next_service,
next_predecessor)` links A→B to B→C, `ncc08.conflicts_with(...)` reports
two completed handovers from one predecessor and service naming different
successors — an ambiguity the convention refuses to settle by timestamp
(§15) — and `ncc08.chain_has_loop(chain)` reports a revisited identity so
a resolver stops rather than following `A -> B -> A` forever (§14).

Scripts hold no wall clock (spec/language.md §9), so `now` flows from a
delivered event's `created_at` or another caller-held timestamp, and a
handler sees one event at a time with no store, so §10's pair check and
the chain walk run over values the caller supplies. Nothing in the
convention transfers authority, service records, locators or capabilities:
it preserves continuity between two identities without making them one
(§19, §30), as `examples/ncc08-rotation-bot.ns` shows while completing a
handover from the successor's side.

### NCC-09 scoped operator authority

`ncc09` implements the delegated-authority convention: a service identity
grants an operator pubkey named scopes for one service through an
addressable kind-30064 grant. The `d` tag binds the pair —
`<service-id>:<operator-pubkey-hex>`, built by `ncc09.address` — and the
grant carries `service`, exactly one operator `p`, `status` (`active` or
`revoked`), one or more `scope` tags, and optional `expiration`,
`valid_from` and `note`. A `publish AuthorityGrant` statement lowers its
fields through the ordinary publication path. Authority is current state,
not history: a later grant under the same `d` replaces the earlier one and
its scopes are never inherited (§14), while a grant revoked with
`status=revoked` grants nothing from then on.

The operator never becomes the service (§4) and the convention defines the
authority container, not what a scope means (§9). Extraction stays pure:
`ncc09.operator`, `ncc09.service`, `ncc09.status` and `ncc09.scopes` read
the grant, and `ncc09.scope_namespace`/`ncc09.scope_is_valid` report the
`ncc:<number>:<action>` and `pubkey:<hex>:<name>` spellings (everything
else is opaque). `ncc09.grant_starts_at(tags, created_at)` renders §6.4's
start — `valid_from` when present, else the event's own time — and
`ncc09.grant_is_valid(tags, now)` is §13: active, exactly one operator, a
service, and `now` inside the `valid_from`/`expiration` window, with a
malformed timestamp failing closed. `ncc09.authorises(tags, scope, now)`
then answers whether that grant delegates the scope, since a valid grant
that does not list it grants nothing. Time always comes from the caller
(spec/language.md §9), as `examples/ncc09-operator-grant-bot.ns` shows.

### NCC-10 service operational state

`ncc10` implements the operational-state convention: a service declares its
current state as an addressable kind-30065 event carrying exactly one
`state` — `operational`, `degraded`, `maintenance`, `unavailable` or
`retiring` (§4) — plus `service` and, optionally, `since`, `expected_until`,
`incident` and `successor`. A direct state is addressed by `d=<service-id>`.
An operator authorised through NCC-09 may also publish, signed with its own
key: its `d` is `<service-pubkey>:<service-id>` (`ncc10.operator_address`)
and it names the principal in a three-column `operator_for` tag
(`ncc10.operator_for_tag`), which only claims a principal — §13 still
resolves the NCC-09 grant before the state is authoritative. A newer event
replaces the older under the same address (§10).

The state is an assertion, never an observation, and `operational` does not
prove reachability (§22); absence of a state is unknown rather than
`operational` (§21), and `expected_until` passing does not change it (§8).
`ncc10.state` and `ncc10.state_service` read the event,
`ncc10.state_is_recognised` checks the five values, and `ncc10.is_direct`,
`ncc10.principal` and `ncc10.operator_service` separate a direct state from
an operator's claim, as `examples/ncc10-status-bot.ns` shows while an
operator publishes under a principal it does not impersonate.

### NCC-11 portable trust policy

`ncc11` implements the portable-policy convention: a kind-30067 addressable
event addressed by a named profile `d` (for example `default`) carries
trust preferences as three-column `rule <key> <value>` tags and
`trust certifier <pubkey>` entries. Rules are namespaced — NCC-defined keys
use `ncc:<number>:<name>`, application keys `pubkey:<hex>:<name>` — and
private rules ride as a NIP-44-encrypted JSON array of tag-shaped arrays in
`content`, combined with the public rules after decryption with the private
entry taking precedence for the policy owner (§16, §17). The module's
`ncc11.rule` and `ncc11.certifier` builders produce those multi-column
values; `ncc11.policy_id`, `ncc11.rule_keys`, `ncc11.rule_value`,
`ncc11.rule_value_is` and `ncc11.certifiers` read them back.

Policy is preference, not authority: it cannot weaken a mandatory protocol
requirement (§22), an unknown rule key is ignored rather than fatal (§24),
and a missing rule means no preference, never allow or deny (§21). A
contradictory duplicate leaves a key unresolved rather than letting tag
order choose (§23), which `ncc11.rule_value` reports as empty.
`ncc11.rule_is_known` names the rules this convention defines and
`ncc11.rule_value_is_valid` checks a value against them — `require`/`prefer`
for key pinning, `allow`/`deny` for the transport and operator rules, a
non-negative integer for `max-stale-age`, and anything for an unknown key.
Named profiles are independent (§19, §20), and which one is active is a
local choice, as `examples/ncc11-policy-client.ns` shows.

### NCC-13 software package release profile

`ncc13` implements the package-release profile: it adds package-manager
metadata to a kind-30063 NIP-51 Release Artifact Set rather than defining a
new event (§2). The module declares that event (`d`, `a`, `version`,
`version_scheme`, `channel`, `source`, `commit`, repeatable `requires`,
`optional` and `conflicts`, and `e` references to NIP-94 artefacts) plus a
minimal `ArtefactMetadata` event for kind 1063, carrying only the `os`,
`arch` and `format` selectors NCC-13 adds to NIP-94 (§15) — the file's
identity, hash and location stay NIP-94's own concern and are not
redeclared. NCC-13 does not define Software Application (kind 32267) or Git
Repository (kind 30617) identity either (§3); scripts read and build those
as plain address text.

`ncc13.version_scheme` and `ncc13.channel` apply the two documented
defaults — an absent scheme reads as `"opaque"` (§8.4), so an unscoped
version string is never assumed ordered, and an absent channel reads as
`"stable"` (§9.1). `ncc13.semver_is_valid` and `ncc13.semver_compare`
implement SemVer precedence over `major.minor.patch` plus an optional
dot-separated prerelease (build metadata is parsed and ignored, per SemVer
§10): equal releases compare equal, a prerelease has lower precedence than
the release it precedes (§11.3), and prerelease identifiers compare
per §11.4 (numeric identifiers compare numerically and always rank below
alphanumeric ones, equal-length ties compare lexically, and a shorter
identifier list with an equal prefix ranks lower). `ncc13.version_satisfies`
judges exactly one `=`/`>`/`>=`/`<`/`<=` constraint (§13); equality works
under any scheme, but a relational operator is scoped to `semver` only,
matching §8.2/§8.3's rule that CalVer and opaque versions are not generically
ordered. §13's multiple-constraints-are-ANDed rule is left to the calling
script folding this function over each constraint tag, the same shape as
NCC-11's rule extraction.

`ncc13.requirement` builds the two-column `requires`/`optional`/`conflicts`
value (a Software Application address and a constraint); `ncc13.requires`,
`ncc13.optional_dependencies` and `ncc13.conflicts` read the repeated tags
back, and `ncc13.requirement_address`/`ncc13.requirement_constraint` split
one entry. `ncc13.operator_for_tag` builds NCC-13's own `operator_for`
two-column tag for the `ncc:13:publish` NCC-09 scope (§33), mirroring
NCC-10's `operator_for` shape rather than inventing a new one.
`ncc13.artefact_matches` judges §19-20's `os`/`arch` selection, with `"any"`
on either side as the platform-independent wildcard; package format
(§19 step 3) is left to the script, since "supported" is local policy
membership rather than an equality the artefact can decide on its own.

`examples/ncc13-release-monitor.ns` publishes a release for one Software
Application, judges every Release Artifact Set it receives against a
tracked installed version and preferred channel, and selects a matching
artefact by platform — the read half is exactly §26-28's discovery and
upgrade-selection model, and NCC-13 itself never installs anything (§27).
