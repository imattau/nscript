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
`Note`) must equal the handler's event type, which for a stream handler is the
stream's name. `signer` (or `author`), `content`, `kind`, `tags` (an array of
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

## Limits

Execution is bounded: a step budget (10,000 by default) and a call depth (32).
A handler that loops or recurses without end stops with
`RuntimeError::ResourceLimit`.

## What does not run, by design or not yet

An unsupported construct is a stable `OperationUnavailable` or
`EvaluationError`, never a silent skip.

- **`Result` values are not modelled.** An operation that fails aborts the
  handler, as `?` would; a script cannot yet branch on a failure. `?` is a no-op
  on the success path.
- **Not evaluated:** `match`, `select`, `fetch`, `latest`, `publish`, `sign`,
  decimals, durations, nested `on`/`every`/`at`/`once`, and `Send`. Publication
  from inside a handler is the largest missing piece.
- **`event` is not statically typed by its source**, so `event.content` is
  checked at run time, not by `nscript check`.
- **The older interpreter** (`Runtime::execute_handler_body*`, and through it
  `run_handler_cycle_with_event_body`) is a separate, text-only path kept for its
  existing callers. It cannot call a module operation. New code should use
  `run_handlers_for_event`.
