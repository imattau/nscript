# RFC 0002: Language surface for Concord and other module-defined protocols

Status: **Draft — proposal for review; nothing here is implemented**

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
