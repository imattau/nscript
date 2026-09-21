# Handler evaluation

`on <stream> { ... }` bodies are run by the evaluator in
`crates/nscript-runtime/src/eval.rs`. The checker has already validated the
program's permissions and effects; the evaluator runs the body and holds the same
line at run time.

```rust
run_handler(&program, &body, Value::from_event(&event), &mut host, EvalLimits::default())
```

`RuntimeSession` is the host to use with a real `Runtime`: `print` becomes a
logged, audited record, and every module operation goes through
`Runtime::invoke_authorized_operation`, so the program's `OperationPolicy`
applies inside a handler exactly as it does outside one.

## What runs

| Construct | Notes |
|---|---|
| `let`, assignment to a declared name | lexically scoped |
| `if` / `else`, `for` over a list, `return` | conditions must be `Bool` |
| integer arithmetic `+ - * / %` | overflow and division by zero are errors |
| `==`, `!=`, `< > <= >=`, `and`/`or` (short-circuit), `!` | ordering is for ints and text |
| `contains`, `in` | text in text, element in list |
| `Ok(x)`, `Err(x)`, `?`, `match` | see Results below |
| text and list literals, records (`Name { field: value }`), indexing | |
| `event.id`, `event.author`, `event.content`, `event.kind`, `event.created_at`, `event.tags` | `tags` iterates as `name=value` text |
| `me` | the program's principal; an error if none is configured |
| `print(x)`, `len(x)` | |
| user `fn`s | recursion allowed; a function sees only its own parameters |
| `module.operation(args)` and the Layer 3 forms that lower to it | arguments become typed `OperationValue`s (`PubKey`, `Text`, `Integer`, `StreamMessage`, records) |

## Running handlers with `nscript run`

`nscript run` is a simulator: every host is a fake, and nothing touches a network
or a key. It now delivers events to handlers and shows what they do.

```sh
nscript run examples/concord-moderation-bot.ns \
    --event '{"content": "buy spam now", "signer": "mallory"}' \
    --event '{"content": "hello", "signer": "alice"}'
```

```
event sim-event (Note, kind 1)
  handler Note: ok
  log info: kicking mallory
  operation concord04.kick_member(PubKey("mallory"))  [simulated]
event sim-event (Note, kind 1)
  handler Note: ok
```

| Option | |
|---|---|
| `--event <json>` | deliver one event; repeatable |
| `--events <file>` | one JSON event per line, or a single JSON array |
| `--as <key>` | the value of `me`; a handler that uses `me` without it fails, and says so |

An event is a JSON object; every field is optional. `event_type` (default
must equal the handler's event type. For `on Note` that is `Note`; for a stream
handler it is the stream's element type, so `stream messages = select
StreamMessage from chat` gives `on messages` the type `StreamMessage`. `signer` (or `author`), `content`, `kind`, `tags` (an array of
`[name, value]`), `created_at`, `id` and `signature` fill in the rest.

- **Matching** uses the same rule as a real subscription: event type, plus the
  handler's author and tag predicates. Only matching handlers run.
- **One failing handler does not hide the others.** A handler that fails prints
  `error[R1004]` and the run exits 1.
- **Operations are simulated.** One a fake host implements really runs. Any
  other is recorded and answered with a benign value of its declared return type
  (a `PublishReport` for the Concord operations), and marked `[simulated]`, so
  you can read off what the script would do. The program's permissions still
  apply, because the checker has already validated them.
- **Startup does not run handler or function bodies.** Only top-level operation
  calls run at startup. Before this, a handler's `kick event.author` was run once
  at startup with its argument dropped, and the whole run failed.

## Typing `event`

A handler's `event` has the type of what it listens to: the named event type for
`on Note`, or the element type of the stream for `on messages` (found through
`stream messages = select StreamMessage from chat`). Its fields are the signed
event's own (`id`, `author`, `pubkey`, `content`, `kind`, `created_at`, `tags`)
plus whatever the type declares in its module (`record StreamMessage { author:
PubKey, content: Text }`, `event Note { content: Text, .. }`) or in the program's
own `event` declaration.

With that, `nscript check` catches, before a script runs:

- **an unknown field**, `event.contnet`, or a record pattern that names one,
  `StreamMessage { authr }`: `E1101`, listing the fields the type has;
- **a wrong argument type**: `kick event.content` passes a `Text` where
  `kick_member` needs a `PubKey`, `E1001`. The type follows a `let`
  (`let who = event.content` makes `who` a `Text`), and `me` is a `PubKey`.

Only certain types are compared, and only plain scalars (`Text`, `Int`, `Bool`,
`PubKey`, `EventId`), so a value whose type the checker cannot tell is never
rejected. A type nothing defines (`on Note` without `use nip01`) is not checked,
and a body that rebinds `event` (`let event = ..`) is left alone.

A field's declared type is what the module says, which is not always what the
evaluator holds: a `Metadata` event declares its `content` as a record, but the
evaluator has the raw JSON text. Access below the first level (`event.content.name`)
is therefore not checked.

## Results

Recoverable operations return `Result<T,E>`, and there are no exceptions. The
evaluator models this as the spec says.

- **An operation declared `Result<T,E>` returns `Ok(value)` or `Err(error)`.** The
  declared type comes from the module descriptor, through
  `OperationHost::declared_return` (the simulator has it; `WithReturns` adds it to
  any other host). An operation with no declared type returns its plain value, as
  before.
- **Only a failure the operation legitimately reports becomes an `Err`:** a
  refusal by the Roster (`AuthorityDenied`), an unreachable relay, a rejected
  publication, a storage conflict, a denied signer, a payment over its limit. The
  error is a record of the operation's declared error type with a `message`.
- **Everything else still aborts the handler:** a capability denial, a wrong
  argument, an unavailable operation, a resource limit. A script must not be able
  to catch a permission boundary or its own programming mistake.
- **`?`** unwraps an `Ok`. On an `Err` it returns that error from the nearest
  enclosing function or handler, so the rest of the body does not run. A value
  that is not a result passes through unchanged.
- **A handler that ends with an `Err`** (by `?` or by `return Err(..)`) has
  failed: its transaction rolls back and it is reported as
  `RuntimeError::HandlerError`. A handler that handles the error itself has not.
- **`match`** works on results (`Ok(v)`, `Err(e)`, nested) with bindings and `_`.
  A value no arm covers is an evaluation error, never a silent fall-through,
  because the checker cannot always prove a match exhaustive (it cannot see the
  type of a call's result).
- **`Ok(x)` and `Err(x)`** are values a script can build and return. A result
  cannot be passed to an operation without being unwrapped.

```nostr
match concord04.kick_member(event.author) {
    Ok(report) => print("kicked " + event.author)
    Err(error) => print("could not kick: " + error.message)
}
```

`nscript run` takes `--fail module.operation` (repeatable) to make the simulator
answer that operation with a recoverable error, so the `Err` path can be
exercised: `--fail concord04.kick_member`. Without it the simulator never fails.

### Patterns

`match` takes every pattern form in the grammar (`spec/grammar.ebnf`):

| Pattern | Matches |
|---|---|
| `_` | anything |
| `x` (lowercase) | anything, binding it to `x` |
| `1`, `-1`, `"a"`, `true`, `none`, `1.5`, `5s`, `50%` | a value equal to the literal |
| `Ok(p)`, `Err(p)` | a result whose payload matches `p` (nested) |
| `None` | `none` (a capitalised name with no payload is a unit variant) |
| `Note { author, content: c }` | a record of that type; `author` binds the field to its own name, `content: c` matches the field against a pattern (any pattern, including a literal) |

An arm may add a guard, `pattern if condition => value`. A guard is evaluated
with the pattern's bindings, and an arm whose guard is false is skipped.

An event is a record named by its type, so `match event { Note { author, content }
if content contains "spam" => .. }` selects on the event's type and fields. Its
fields are `id`, `author` (also `pubkey`), `content`, `kind`, `created_at` and
`tags`.

An arm's value ends at its line, so the next line can start a new arm (`-3 => ..`
is a pattern, not a subtraction from the previous value). Inside brackets, a
value may still span lines.

The checker treats a guarded arm as one that may not match: it is not a catch-all
(so the arm after it is reachable), and it does not cover its variant, so a
`Result` match that handles `Ok` only under a guard is `E1301`. A variant whose
payload tests a literal (`Ok(1)`) covers only that value.

**Not supported.** The grammar allows an arm's value to be a block; the syntax
tree has no block expression, so an arm's value is an expression.

## Subscription cycles

`Runtime::run_evaluated_cycle` runs a whole subscription cycle with the
evaluator: for each handler it subscribes, polls, and dispatches each delivered
event through `dispatch_evaluated`, then unsubscribes. It is
`run_handler_cycle_with_event_body` with the evaluator as the body engine, so a
handler can call module operations.

Each dispatch keeps the transactional discipline of the original cycle: the event
must match the subscription, is claimed for idempotency, runs inside a storage
transaction that commits only if the body succeeded, and is audited as
`committed` or `rolled_back`. A handler that fails is reported in
`CycleReport::failures` and does not abort the cycle.

Two things are scoped per handler and per subscription, not runtime-wide:

- the **idempotency claim** is keyed by handler and event, so redelivery to one
  handler is suppressed while a second handler on the same event still runs;
- the **poll dedupe** (dropping an event that arrives from several relays) is
  keyed by subscription.

Both used to be keyed by event id alone, so when two handlers subscribed to the
same events the first consumed each one and the second never ran. The original
cycle had the same defect and is fixed too.

## Limits

Execution is bounded: a step budget (10,000 by default) and a call depth (32).
A handler that loops or recurses without end stops with
`RuntimeError::ResourceLimit`.

## What does not run, by design or not yet

An unsupported construct is a stable `OperationUnavailable` or
`EvaluationError`, never a silent skip.

- **Not evaluated:** `select`, `fetch`, `latest`, `publish`, `sign`, decimals,
  durations, nested `on`/`every`/`at`/`once`, and `Send`. Publication
  from inside a handler is the largest missing piece.
- **The older interpreter** (`Runtime::execute_handler_body*`, and through it
  `run_handler_cycle_with_event_body`) is a separate, text-only path kept for its
  existing callers. It cannot call a module operation. New code should use
  `run_handlers_for_event`.
