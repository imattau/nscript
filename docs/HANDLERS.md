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
- **Not wired into `nscript run`.** The command still only registers
  subscriptions. The evaluator is a library; a host that delivers events calls
  `run_handler` per event.
- **`event` is not statically typed by its source**, so `event.content` is
  checked at run time, not by `nscript check`.
- **The older interpreter** (`Runtime::execute_handler_body*`) is a separate,
  text-only path kept for its existing callers. New code should use this one.
