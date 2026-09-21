# RFC 0002: Language surface for Concord and other module-defined protocols

Status: **Draft — read side partly implemented (see Implementation notes); scoped grants and fold queries still proposals**

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

**Still blocking, and not language design.**

- **Handler bodies are not evaluated.** `nscript run` registers subscriptions
  and stops; `PLAN.md` lists full handler and stream evaluation as deferred.
  Until an evaluator exists, `on chat.message { print(event.content) }` checks
  but cannot run, however the Concord side is built.
- **`event` is not typed by the source.** A handler over a Concord stream checks
  as an untyped handler; `event.content` and `event.author` are not validated
  against `StreamMessage`.
- **Where does a script get a `DerivedKey`?** This is open question 3, and it is
  now concrete: the language has no way to bind a host-held key to a name. The
  `me` principal is the only host-provided value today. `concord01.stream(key)`
  passes an undefined identifier that the checker does not resolve.
- **Scoped grants (section 2) and fold queries (section 3)** are untouched.

