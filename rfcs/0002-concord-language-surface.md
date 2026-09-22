# RFC 0002: Language surface for Concord and other module-defined protocols

Status: **Draft — read side and fold queries (section 3) implemented (see Implementation notes); scoped grants (section 2) still a proposal**

## Abstract

Concord (see `docs/CONCORD.md`, `docs/cord/`) is currently usable from NScript
only through typed module operations such as
`concord04.kick_member(alice)`. That is deliberately within the existing
language. This RFC asks whether the language should grow a small, general
extension so that protocol modules can offer streams and authority-scoped
permissions in the language's own idiom, without any Concord-specific compiler
support.

The design constraint from `PLAN.md` stands: Concord semantics stay in modules;
the compiler gains only generic typed-module, effect, capability and stream
infrastructure.

## Current state (no syntax change)

Works today, checked and covered by `conformance/valid/concord*.ns`:

```nostr
use concord04

permissions {
    concord_kick
}

let result = concord04.kick_member(alice)
```

Permissions are per-operation names declared by the module descriptor. The
checker rejects an ungranted call (`E3001`), and the host separately enforces
CORD-04 rank at run time. What is missing is the read side and any way to say
*where* a grant applies.

## Gaps

1. **No module-defined event source.** `stream` and `on` (spec §5) are
   defined only over `select ... from <relayset>`. A Concord channel is not a
   relayset: it is a key-addressed, decrypted, authority-folded stream.
2. **No scoped grants.** A bot should hold `Kick` *in one community*, not
   everywhere. Operation-level permission names cannot express the scope.
3. **No fold-derived queries.** `community.can(me, Ban, target)` reads folded
   state and is not an operation with an effect.

## Proposal

### 1. Module-provided sources for `select`/`stream`

Allow a module to declare a *source type*, and allow the `from` clause of
`select` to take a value of a source type in addition to a relayset:

```nostr
use concord01

let chat = concord01.stream(channel_key)          // value of nominal type Stream

stream messages = select StreamMessage from chat

on messages {
    print(event.content)
}
```

`event` keeps the existing rule: immutable, of the stream's signed event
type, possibly delivered more than once. The module is responsible for the
wire work (unwrap, validation, binding checks, decryption) and MUST surface
only events that passed it. Existing `stream`, `on`, idempotency and store
rules apply unchanged.

### 2. Scoped permissions

Generalise the permission production so a module verb may name a scope value
using the existing `from`/`to` position style:

```nostr
permissions {
    concord Kick in devs
    concord Ban in devs
    read StreamMessage from chat
}
```

Grammar sketch, extending `permission` in `spec/grammar.ebnf`:

```ebnf
permission = ... existing forms ...
           | identifier, identifier, [ "in", identifier ], terminator ;
           (* module-namespace, module-declared verb, optional scope *)
```

The verb must be declared by an imported module descriptor; unknown verbs are
`E3001`-class errors. A scope is a program value; grants apply only to
operations invoked with that scope. Descriptors gain an optional
`permission concord.Kick scope Community` clause replacing today's flat names.

### 3. Fold queries as pure functions

Fold-derived reads (`can`, `rank`, `is_staff`) are host-provided *pure
functions* over folded local state, callable in expressions, and typed
`Bool`. This also removes the `Int` 0/1 workaround and the `Storage` effect
that `can_kick` uses today only because descriptors require an effect.

## Non-goals

- No Concord keywords, and no compiler knowledge of roles, epochs or ranks.
- No way for a script to obtain key material; `SharedSecret`, `DerivedKey`
  and `SignedBytes` remain opaque (`spec/host.md`).
- No change to at-least-once handler semantics.
- No weakening of the hardened-agent profile: effects exposed by a module
  operation still propagate transitively.

## Compatibility

Purely additive. Programs using flat operation permissions keep working. Modules
that do not declare a source type or scope are unaffected.

## Security considerations

- Scoped grants shrink authority; they never widen the program's own
  capability set. The run-time Roster check remains the final gate, so a
  misconfigured grant cannot exceed what the acting identity holds.
- A source's validation failures MUST NOT surface partial events.
- Scope values are opaque handles; printing one MUST NOT reveal keys.

## Open questions

1. Is a second kind of `from` operand acceptable, or should sources be a
   subtype of relayset?
2. Should permissions stay flat names with scope encoded in the descriptor, in
   which case sections 2 and 3 shrink to a descriptor-schema change only?
3. Where does a scope value come from (`concord.open(invite)`), and how is it
   provisioned under the hardened profile?
4. Should fold queries be allowed inside `select` predicates?

## Test plan

Add `conformance/valid` and `conformance/invalid` fixtures mirroring the
examples above (ungranted verb, wrong scope, unknown verb, source-typed
`select`), extend `spec/diagnostics.md`, and add module-schema coverage in
`spec/module-schema.ebnf` before any implementation is merged.

## Implementation notes (2026-09-21)

Starting on the read side showed that much of section 1 needs no language
change, and that the real dependency is elsewhere.

**Already true today.** The parser accepts `select T ... from <expression>`, and
the checker treats `from <identifier>` as a named source, requiring the
permission `read T from <identifier>`. So `stream messages = select
StreamMessage from chat` and `on messages { ... }` already parse and check.
This answers open question 1: no second kind of `from` operand is needed at the
syntax level. What makes a value a *source* is the module operation that
produced it, not a new grammar production.

**Added.** `concord01` now declares `nominal Stream` and
`operation stream(key: DerivedKey) -> Stream effect Relay,Decrypt permission
concord_read`. The runtime has a matching `StreamHandle` value carrying only the
plane's public address (no key material), and the real host implements the
operation. `conformance/valid/concord-read-stream.ns` is the section 1 example
as a checked program; opening a stream needs `concord_read` in addition to
`read StreamMessage from chat`, and the negative fixture pins that.

**The substance behind `on`.** `ChannelReader` (in `nscript-host-crypto`) turns
raw wraps into what an honest client would show: events that open under the
plane key, are bound to the Channel and epoch, have not expired (by their own
signed tag), come from unbanned authors, are not duplicates, and are ordered by
`(time_ms, id)`. Run against a live community it delivered all 7 real events
once each and dropped the 20 cross-relay duplicates.

**Found while doing it.** Two checker holes let a program that could not be
checked pass silently, both now `E1101`: calling an operation an imported
module does not declare, and calling into a module with no `use`. Malformed
statements and leftover tokens were also being dropped silently (see
`docs/LAYER3.md`).

**Blockers, updated.** Handler evaluation, the largest one, now exists (see
`docs/HANDLERS.md`): a bounded evaluator runs handler bodies, calls module
operations through the policy gate, and is proved end to end by a moderation bot
that reads a real encrypted channel and kicks a spammer
(`nscript-host-crypto/tests/handler.rs`). It is wired into `nscript run --event`, which simulates
with fake hosts. What remains:

- **`event` is now typed by the source** (see `docs/HANDLERS.md`): `on messages`
  over `select StreamMessage` gives `event` the type `StreamMessage`, its fields
  are checked, and its values are checked against operation parameters. A stream
  handler's event type is also the element type now, so a received
  `StreamMessage` matches it.
- **Where does a script get a `DerivedKey`?** This was open question 3; it is
  now answered by `key name = host("label")`, a new declaration resolved by the
  checker as `DerivedKey`. The script gets an opaque handle: it can pass it to
  an operation but never read, print or convert the bytes. `nscript run`
  derives a deterministic, non-secret stand-in per label;
  `Nip44OperationHost::with_key` provisions a real one. See
  `examples/concord-key-bot.ns`.
- **Publication from a handler is not evaluated.** `Result` values are now
  modelled (see `docs/HANDLERS.md`): a handler can `match` on an operation's
  `Ok`/`Err`, use `?`, and a kick the Roster refuses reaches the script as an
  `Err` it can read.
- **Scoped grants (section 2)** are untouched.

Writing the evaluator's first handler also exposed a parser bug: a lowercase
name before a block, as in `if ready { ... }`, was read as a record literal, so
any condition ending in a bare variable failed to parse. Record types are
capitalised, so only a capitalised name now opens a record literal. That bug
was also why `examples/private-message.ns` failed `check`.

## Implementation notes (2026-09-22): fold queries (section 3)

Section 3 proposed fold-derived reads as pure functions, typed `Bool`,
replacing the `Result<Int,E>`/`Storage` workaround `can_kick`/`can_ban` use
today because the language had no boolean result. That workaround is
untouched (changing a shipped, descriptor-stable operation is a separate,
riskier change); what landed is the general mechanism, plus two new fold
queries built on it.

**The grammar already had the right shape.** `function` declarations
(`spec/module-schema.ebnf`) take no `effect` and no `permission` — exactly
what a pure read needs — but were never reachable from a running handler: the
evaluator treated every `module.name(args)` call as a gated operation call,
and `PureFunctionHost` (used for `nip19`) was wired to nothing. Two new
`OperationHost`/`EvalHost` methods fix that: `is_pure_function` (true only for
the fold queries the trait itself implements, as default methods — no host
ever overrides it) and `call_pure_function` (no permission gate, no effect, no
`Ok`/`Err` wrapping, an `OperationValue::Bool` round-trips through `Value` like
any other scalar). A member call the checker resolved to a `function` (rather
than an `operation`) routes through this path.

**Two concrete queries**, both backed by protocol logic already tested from
earlier CORD-05/06 work, both callable with no permission declared anywhere in
a script:

- `concord05.invite_is_valid(bundle: Text, now: Int) -> Bool` — an invite
  bundle's own structure, owner self-certification and (given the caller's
  clock) expiry, with no relay and no key touched.
- `concord06.commitment_matches(held_key: DerivedKey, held_epoch: Int,
  commitment: Text) -> Bool` — CORD-06 §4 continuity: whether a key the script
  already holds (an opaque handle, e.g. from `key name = host(...)`),
  compared at `held_epoch`, reproduces a rotation's committed tag, so a script
  can decide whether a rekey notice is worth acting on before spending the
  effort to apply it.

**Argument type-checking now covers `function`s too**, not just `operation`s
(`nscript-semantics/src/events.rs`): a wrong scalar type on either kind of
call is `E1001`, the same as before.

**Left for later, as this RFC's own non-goals and open questions already
flagged:** fold queries are usable only inside handler bodies, where the
evaluator runs; a top-level call is collected like any other operation call
and would fail as unavailable, since `run_operations` does not know about
`is_pure_function`. Whether that also belongs in `select` predicates (open
question 4) is untouched. `can_kick`/`can_ban` were not migrated to `function`
form. Section 2 (scoped grants) remains a proposal.
