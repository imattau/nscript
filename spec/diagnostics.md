# Diagnostics

Status: **Draft 0.1 — normative**

Machine-readable diagnostics contain `code`, `severity`, `message`, `primary`
source span, zero or more labelled secondary spans, notes, and optional fixes.
Human rendering may vary, but codes and semantic categories are stable within a
language major version.

## Initial registry

| Code | Category | Required condition |
| --- | --- | --- |
| E1001 | nominal-type-mismatch | Distinct nominal Nostr types are combined without an explicit conversion |
| E1101 | unknown-name | A name cannot be resolved in lexical or module scope |
| E1102 | module-call-arity | A module function or operation receives the wrong number of arguments |
| E1201 | invalid-event-declaration | Event kind, fields, or replacement mode violate its NIP module |
| E1301 | non-exhaustive-match | A closed type is not covered by a match |
| E1302 | unreachable-pattern | A prior pattern covers the arm completely |
| E2001 | invalid-tag | A typed tag fails its module's construction rules |
| E2201 | unsigned-publication | Publication receives `Unsigned<E>` without an allowed signer |
| E2202 | signer-type-mismatch | A signer policy cannot sign the requested event type or author |
| E2203 | missing-default-signer | Bare unsigned publication has no declared signer default |
| E2204 | missing-default-relays | Publication without `to` has no declared relay-set default |
| E2401 | unbounded-local-filter | A non-lowerable query predicate lacks a finite remote bound |
| E3001 | missing-permission | A reachable inferred effect is not covered by the manifest |
| E3002 | unavailable-capability | The host cannot provision a declared mandatory capability |
| E3101 | high-risk-consent-required | Secret, filesystem, or payment authority lacks distinct consent |
| E4001 | module-cycle | Imports contain a dependency cycle |
| E4002 | incompatible-module | A module's language or dependency range cannot be resolved |
| E4003 | invalid-module-schema | A module schema is malformed, conflicting, or non-deterministic |
| E5001 | profile-capability-denied | A runtime profile categorically forbids a type, effect, or permission |

Operational failures returned as `Result` values are not compiler diagnostics.
An unhandled top-level `Err`, supervision action, or host provisioning failure
uses the same structured envelope with an `R`-prefixed runtime code.

## Security and reproducibility

Diagnostics MUST redact `SecretKey`, credential, decrypted plaintext, and payment
authorization values. Debug mode does not weaken this rule. Event contents and
public keys may be logged unless the relevant module marks them sensitive.

Conformance tests compare code, severity, primary span, and normalized message
arguments. They do not compare colors, surrounding source lines, or prose notes.
Suggested fixes MUST parse and MUST NOT broaden program permissions silently.
