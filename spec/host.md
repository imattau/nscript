# Host capability contract

Status: **Draft 0.1 — normative**

NScript runtimes implement effects through typed host capabilities. A capability
is an unforgeable handle created from the program manifest after user or operator
approval. Source code cannot enumerate undeclared host resources.

## Common rules

All capability calls receive an invocation ID, cancellation token, and resource
budget. Calls return `Result<T,E>` and never inject exceptions into the language.
Cancellation may prevent a call or stop waiting for its result; it cannot retract
an external side effect already accepted.

Hosts record structured audit entries for signing, publishing, HTTP, filesystem,
payment, logging, and direct secret-key operations. Audit records include
program and package identity, operation, target, result, and time, but exclude
plaintext secrets and encrypted-message contents.

## Runtime profiles

The `standard` profile exposes only explicitly declared and host-approved
capabilities. The `hardened-agent` profile applies an additional non-overridable
deny set before effect checking. It forbids direct or transitive use of
`SecretKey`, `Nsec`, `secret_key`, filesystem mounts, raw sockets, process or
shell execution, native plugins, ambient credentials, and HTTP permissions that
are not a finite list of normalized HTTPS origins.

The hardened profile permits declared relay sets, NIP-46 or equivalently isolated
signers, origin-scoped HTTPS, bounded storage, encryption, decryption, clock,
logging, and payment only when the host policy independently permits them. A
dependency requesting a forbidden type, effect, or permission makes the whole
program invalid; unused forbidden declarations are still rejected. Hosts cannot
weaken the deny set, though they may deny additional capabilities.

## Relay

The relay capability provides:

```text
query(filters, relayset) -> Result<List<Signed<Event>>, RelayError>
subscribe(filters, relayset) -> Result<Subscription, RelayError>
publish(event, relayset) -> Result<PublishReport, RelayError>
```

`PublishReport` contains a result for every resolved relay. Subscription items
include the event and relays from which it was observed. Relay URLs are
normalised before permission comparison. Dynamic relay discovery is allowed only
inside a declared relay set whose policy permits discovery.

## Signer and secret keys

The signer capability provides public-key discovery and event signing. It may be
backed by NIP-46, a browser extension, hardware, or a local keystore. Backend
choice does not change the NScript interface.

Direct `SecretKey` import or generation requires `secret_key`. A secret can be
used only to construct an in-memory signer; it cannot be converted to `Text` or
`Bytes`, stored, logged, returned from the program, or sent through another
capability. Hosts SHOULD disable this capability for remotely supplied scripts.

## Encryption

NIP modules expose typed `encrypt` and `decrypt` functions backed by host
capabilities. Permissions constrain the envelope event type and signer handle.
Decryption returns authenticated plaintext only after all module-required sender,
recipient, and wrapper validation succeeds. A runtime MUST NOT expose partial
plaintext on error.

## Storage

The storage capability offers typed key/value operations, iteration with an
explicit bound, compare-and-swap, and transactions. Values use a canonical,
versioned encoding. Store names are scoped by package identity and major version
unless a migration explicitly adopts older data.

Durability after commit is host-defined but must be reported as one of
`memory`, `process`, or `durable`. Programs may require a minimum class in their
manifest.

## HTTP

```nostr
let weather = fetch json from "https://api.example.com/weather"
```

HTTP supports HTTPS by default. Each request method, normalized origin, redirect
target, request size, response size, and timeout is checked against the declared
permission. Credentials are named host secrets referenced by handle; source code
cannot read their values. DNS rebinding and redirects do not bypass origin checks.

Wildcard origins, plain HTTP, host-supplied ambient allowlists, and URLs derived
from undeclared origins are forbidden in the hardened-agent profile.

`fetch text`, `fetch bytes`, and `fetch json` return `Result` values. JSON is
decoded into a module- or call-specified type and rejects unknown or missing
fields according to that type's declaration.

## Filesystem

Filesystem access is optional and high risk. Permissions grant read or write to
named host mounts, never arbitrary OS paths. Paths are relative, normalized, and
cannot escape a mount through traversal or links. Writes are atomic where the
host supports them. No shell or executable-process capability exists in the core
language.

## Payments

Payment modules create typed payment intents. `Payment` permission constrains
protocol, maximum amount, recipient policy, and optional period budget. Creating
an intent and authorizing transfer are separate operations. Hosts MUST obtain
interactive approval unless a matching pre-authorized budget exists.

## Clock and timers

The clock returns UTC instants and schedules wakeups. Civil-time conversion uses
the manifest timezone and the host timezone database. Tests can replace it with
a deterministic clock. Hosts document their timer precision; programs must not
assume sub-second precision unless the host advertises it.

## Logging

`print` and structured logging require `log`. Hosts bound message size and rate,
label output with program identity, and apply module sensitivity and secret
redaction before emission. Logging never bypasses `SecretKey` or credential
non-serialization rules.

## Resource limits and failure taxonomy

Capability errors are closed enums per interface and include denial,
unavailability, timeout, cancellation, malformed response, size limit, and
backend-specific rejection. Unknown backend failures map to a stable `Other`
case with a redacted diagnostic identifier.

Resource limits are evaluated independently of permissions. Permission says an
operation is allowed; a budget controls how much of it may occur. Exhausting a
budget stops or supervises the current invocation without broadening authority.
