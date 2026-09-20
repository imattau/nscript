# Runtime scenarios

## Duplicate delivery and atomic claim

Feed the same valid signed note through two relays concurrently, commit the
handler, restart the runtime, then redeliver it. Concurrent copies produce one
active invocation. Redelivery after restart is permitted; wrapping the body in
`once(event.id)` makes its store mutations occur once.

## Signer denial

Grant the program's static signing permission but configure the NIP-46 signer to
deny the event kind. Signing returns `Err(SignerDenied)` and nothing is sent to a
relay. No local-key fallback occurs.

## Partial publication

Have one relay accept, one reject, and one time out. Publication returns all
three outcomes and is classified as accepted. A caller requiring quorum can
reject that outcome explicitly.

## Transaction rollback

Mutate a store and then propagate a relay error from a handler. Store mutations
roll back. Any relay event already accepted remains published.

## Timer overlap

Advance a fake clock beyond two intervals while an `every` body is active. No
second invocation starts. The next interval begins after the first body ends.

## HTTP redirect denial

Allow `api.example.com`, then return a redirect to `other.example`. The runtime
returns `Err(HttpOriginDenied)` without contacting the second origin.

## Secret redaction

Grant `secret_key`, trigger a diagnostic while a `SecretKey` is in scope, and
verify that source logs, structured diagnostics, and crash reports contain no
key bytes or encoding.
