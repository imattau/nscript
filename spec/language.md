# NScript language and runtime

Status: **Draft 0.1 — normative**

## 1. Programs and modules

An NScript program is a UTF-8 source file. Top-level declarations are evaluated
in source order after module loading and static checking. Imported NIP modules
provide types and lowering rules; importing a module performs no I/O.

```nostr
use nip01
use nip19
use nip46
```

Module dependencies form a directed acyclic graph. Cycles are a compile error.
Unqualified duplicate exports are ambiguous and MUST be rejected. A runtime MUST
record the exact module versions used to compile a program.

Programs select one runtime profile, defaulting to `standard`:

```nostr
runtime hardened-agent
```

The hardened-agent profile is defined by the host specification and is checked
before module initialization or host capability provisioning.

## 2. Values and types

NScript is statically typed. The core value types are:

```text
Bool  Int  Decimal  Text  Bytes  Duration  Percentage  Unit  Never
List<T>  Set<T>  Map<K,V>  Option<T>  Result<T,E>
```

Nostr modules add nominal types. At minimum these include `PubKey`, `EventId`,
`Signature`, `RelayUrl`, `Timestamp`, `Kind`, `Npub`, `Nprofile`, `Nevent`,
`Naddr`, `Nsec`, `NoteId`, `Signer`, and `SecretKey`. Nominal types do not
implicitly convert even when their wire representations are identical. `Nsec`
has the same copy, serialization, logging, and permission restrictions as
`SecretKey`.

`SecretKey` is non-copyable, non-serialisable, non-printable, and unavailable
unless the host grants `secret_key`. A conforming diagnostic MUST redact its
value. Normal programs use a `Signer` capability instead.

Local bindings are immutable unless introduced with `var`. Function parameter
and return types are mandatory at public module boundaries; local types MAY be
inferred. There are no truthy conversions and no null value. Exhaustive matching
is required for enums, `Option`, and `Result`.

## 3. Events and tags

An event declaration describes author-controlled fields and its Nostr lowering:

```nostr
event Note {
    kind: 1
    content: Text
    tags: List<Tag> = []
}
```

Constructing `Note { content: "hello" }` yields `Unsigned<Note>`. The runtime
supplies `created_at`; the signer supplies `pubkey`, `id`, and `sig`. Signing
yields `Signed<Note>`. These wrapper states are distinct and cannot be cast.

Event declarations may include exactly one of:

```nostr
replaceable
parameterised by identifier
ephemeral
```

The compiler validates the selected mode against the event kind rules supplied
by the declaring NIP module. Parameterised events MUST lower their identifier to
exactly one `d` tag.

A `publish` of a record lowers each author field to a two-column tag named
after the field. `Text`, `Int`, `Bool` and `PubKey` values lower to their text
form; each element of a `List` field lowers to a repeated tag of the same name.
The `content` field is the event's content rather than a tag. The `tags` field
and the bookkeeping fields `id`, `author`, `pubkey`, `kind` and `created_at`
are read-side only and MUST NOT lower to tags. For a parameterised declaration
the identifier field lowers to the single `d` tag instead of its own name, and
publishing such a record with zero or more than one identifier field is an
error. The event's kind and mode come from the visible `event` declaration —
the program's own or an imported module's — falling back to `Note` as kind 1
(and any other name as kind 0) only when no declaration is visible. Values
computed at run time lower by the same rules at the publication site; a
computed value that is not a scalar or a list of scalars is an error there.

Tags are algebraic values, not lists of strings. For example,
`Person(alice)` and `ReplyTo(parent)` lower according to their module definition.
Unknown tags are preserved as `RawTag` when reading but require the explicit
`raw_tags` permission when publishing.

## 4. Functions, results, and effects

Functions are expression-capable blocks. The last expression is returned when
there is no explicit `return`. Recoverable operations return `Result<T,E>`.
Postfix `?` returns the error from the nearest enclosing function or handler.
NScript has no exceptions.

The compiler infers a closed effect set for every function. Standard effects are
`Relay`, `Sign`, `Encrypt`, `Decrypt`, `Storage`, `HTTP`, `Filesystem`, `Payment`,
`Clock`, and `Log`. Pure functions have an empty set. Effects propagate through
calls and generic callbacks. Recursion is permitted but subject to host resource
limits.

Every reachable effect must be covered by a top-level permission. Unused
permissions produce a warning. Dynamically constructing authority is forbidden.

```nostr
permissions {
    read Note from public
    publish Alert to public
    sign Alert with account
    storage SeenEvents
    http "api.example.com"
    clock
    log
}
```

Permission matching is structural and least-privilege: an event type, operation,
signer, relay set, store, and HTTP origin must match where applicable. Redirects
require the destination origin to be allowed. `filesystem`, `payment`, and
`secret_key` are high-risk permissions and MUST receive distinct host consent.

Programs may declare publication defaults using existing named capabilities:

```nostr
defaults {
    signer: account
    relays: public
}
```

There may be at most one defaults block. Referenced declarations must exist in
the same program or an imported manifest fragment and must have type `Signer`
and `RelaySet`, respectively. Defaults grant no permission by themselves.

## 5. Queries and streams

`select` produces a finite `Result<List<E>, RelayError>`. A query compiler MUST
lower supported predicates to Nostr filters. A predicate that cannot be lowered
MAY run locally only when its remote superset is bounded by an explicit `limit`,
`since`, or `until`; otherwise compilation fails.

```nostr
let notes = select Note
    where author == alice and tags.t contains "nostr"
    since 24h
    limit 100
    from public
```

Multiple filters are permitted when required by Nostr's OR semantics. Results
are deduplicated by `EventId`, validated before exposure, ordered by
`created_at` descending then `EventId` ascending, and truncated after merging.

Conjunctive predicates that cannot share one NIP-01 filter require separate,
bounded relay queries followed by local intersection; they MUST NOT be placed as
multiple filters in one `REQ`, because filters within a request are alternatives.

A `stream` is an unbounded subscription. `on` registers a handler and does not
block top-level registration of later handlers.

```nostr
stream mentions = select Note where tags.p contains me from public

on mentions {
    print(event.content)
}
```

Inside a handler, `event` is immutable and has the stream's signed event type.
Handlers MAY observe an event more than once. Programs requiring idempotency
must use event IDs with a transactional store operation.

`me` is an optional host-provided `PubKey` identifying the program's principal.
It grants no signing authority and has no value unless configured before
execution. Programs that require `me` fail during capability provisioning when
the host provides no principal.

## 6. Signing and publication

Signer declarations create named handles; they never reveal key material.

```nostr
signer account = nip46()
let signed = sign note with account
publish signed to public
```

`publish unsigned to public with account` is shorthand for signing followed by
publication. The compiler MUST reject publication without a signer when the
value is unsigned. Publication returns a per-relay outcome and succeeds at the
language level when at least one target relay accepts the event; callers can
inspect or require a stricter acknowledgement policy explicitly.

`publish` is an effectful expression returning
`Result<PublishReport, RelayError>`. At statement position its result may be
discarded with a warning; functions and workflows may return or inspect it.
The record's author fields lower to wire tags as specified in §3.

For each omitted `with` or `to` clause, the compiler substitutes the matching
source-declared default before type, effect, and permission checking. An unsigned
event with no signer default produces `E2203`; any event with no relay default
produces `E2204`. Hosts MUST NOT supply ambient publication defaults. Explicit
clauses override defaults at that publication site without changing them.

A signer denial, disconnect, invalid signature, or public-key mismatch is a
typed error. The runtime MUST recompute and validate the event ID and signature
before publishing.

## 7. Relays and delivery

Relays and relay sets are named capabilities:

```nostr
relay social = "wss://social.example"
relayset public = configured
```

The host owns DNS, WebSockets, authentication, reconnects, backoff, EOSE, and
connection pooling. Programs cannot open sockets directly. Reconnect uses
exponential backoff with jitter and resumes from the last committed handler
checkpoint where available.

Delivery is at least once. The runtime validates event IDs and signatures,
deduplicates concurrently received copies, but MAY redeliver after restart or
checkpoint failure. Within one handler invocation, effects execute in source
order. Different invocations may run concurrently unless the handler is marked
`serial`.

## 8. Stores and transactions

Stores are typed, local, host-provided capabilities:

```nostr
store SeenEvents<Set<EventId>>

store Profiles {
    key: PubKey
    value: Metadata
}
```

Each handler invocation runs store mutations in a transaction. Successful
completion commits; propagated errors, cancellation, and resource termination
roll back. Relay publication and other external effects are not rolled back.
`once(event.id) { ... }` atomically claims an event ID and is the standard
idempotency primitive.

Store schemas are versioned by the program. Incompatible changes require an
explicit migration; a runtime MUST NOT discard data automatically.

## 9. Time and scheduling

`every` schedules intervals measured from the end of the preceding invocation;
invocations therefore do not overlap. `at` uses the manifest timezone, defaulting
to UTC, and runs once for each matching civil time. Missed schedules are not
replayed unless the declaration opts into `catch_up`.

All access to wall time requires `clock`. Event timestamps supplied by the host
do not. Tests MAY replace the clock with a deterministic host implementation.

## 10. Pattern matching

Patterns destructure events, tags, records, enums, and result values. Alternatives
are tested top-to-bottom; only the selected arm executes. Guards must be pure.
The compiler rejects unreachable arms and non-exhaustive matches on closed types.

```nostr
match event {
    Note { author, content } if author == alice => print(content)
    Metadata { profile } => Profiles.put(event.pubkey, profile)?
    _ => ignore
}
```

## 11. Execution and supervision

After static validation and host permission approval, the runtime:

1. loads modules and validates their versions;
2. provisions declared capabilities;
3. evaluates pure top-level bindings in source order;
4. registers streams and schedules in source order; and
5. enters the event loop.

I/O suspension is implicit; source-level `async` and `await` do not exist.
Cancellation is observed only at effect boundaries. A handler failure rolls back
its store transaction, records a structured diagnostic, and applies the host's
bounded retry policy. Retries preserve the same input event and receive a new
attempt number. Permanent errors are dead-lettered when the host provides such a
sink; otherwise they are logged and processing continues.

Hosts MUST bound memory, instruction count or execution time, concurrent
handlers, open subscriptions, response size, store usage, and log volume. Limit
termination is a typed supervision outcome, not catchable program control flow.

## 12. Host portability

Interpreter, WASM, JavaScript, and native backends must expose the same capability
interfaces and observable ordering. A sandboxed program cannot access sockets,
files, keys, clocks, randomness, or native APIs except through a granted host
capability. A backend MAY optimise pure computation but MUST preserve effects.

The intended Nostr IR operations include `CreateEvent`, `SignEvent`,
`PublishEvent`, `Subscribe`, `Query`, `Encrypt`, `Decrypt`, `StoreTransaction`,
`Schedule`, and capability-scoped HTTP/filesystem/payment operations. The IR
encoding is not yet a stable public interchange format.

## 13. Diagnostics

Diagnostics include a stable code, severity, source span, primary message, and
actionable note. Required errors include nominal type mismatch, missing
permission, unsigned publication, invalid event-kind mode, unbounded local
filtering, non-exhaustive match, module cycle, and unavailable capability.
Secrets and encrypted plaintext MUST be redacted from diagnostics by default.
