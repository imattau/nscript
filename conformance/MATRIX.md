# Conformance coverage matrix

This matrix tracks the minimum corpus required before Draft 0.1 can be promoted
to a release candidate. “Fixture” means a source test; “scenario” means a test
against deterministic host fakes.

| Area | Positive | Negative | Runtime vector |
| --- | --- | --- | --- |
| Nominal Nostr types | `nip19.ns` | `nominal-type.ns` | — |
| Event construction and signing state | `hello-note.ns` | `unsigned-publish.ns` | Signer denial |
| Permission/effect checking | `mentions.ns` | `missing-permission.ns` | Capability denial |
| Publication defaults | `default-publish.ns` | `missing-default-signer.ns`, `missing-default-relays.ns` | Inspect publication expansion trace |
| Hardened-agent profile | `default-publish.ns` | `hardened-secret-key.ns`, `hardened-filesystem.ns` | Transitive dependency denial |
| Declarative NIP modules | `modules/valid/nip10.nsm` | `modules/invalid/dynamic-wire-name.nsm` | `vectors/module-descriptors.json` |
| Secret-key isolation | `secret-with-capability.ns` | `secret-without-capability.ns` | Secret redaction |
| Query lowering and bounds | `mentions.ns` | `unbounded-local-filter.ns` | Inspect filter lowering trace |
| Pattern exhaustiveness | `exhaustive-match.ns` | `non-exhaustive-match.ns`, `unreachable-pattern.ns` | — |
| At-least-once handlers | `idempotent-handler.ns` | `dispatch_event` runtime test | Duplicate delivery |
| Store transactions | `idempotent-handler.ns` | `dispatch_event_transactional` runtime test | Transaction rollback |
| NIP-19 round trips | `nip19.ns` | Runtime invalid-input tests | Runtime npub round-trip vector |
| NIP-46 validation | `hello-note.ns` | Dedicated signer-provision host test | Signer denial |
| Typed tags | `mentions.ns` | Runtime wire-tags test | Serialization |
| Replaceable events | `replaceable.ns` | `invalid-event-mode.ns` | Tie-break vector planned |
| Timers | `timer.ns` | Runtime timer validation | Timer overlap |
| HTTP origin policy | Example only | Dedicated HTTP host test | Redirect denial |
| Partial relay publication | `hello-note.ns` | Runtime partial-publication test | Partial publication |
| Package resolution | Resolver transitive-version tests | Missing/incompatible package tests | Resolver version-selection vector |

The Draft 0.1 release-blocker cells for defaults, query lowering, and
hardened-agent capability isolation are covered by executable vectors or
inspectable traces. Replaceable-event tie-breaking remains a follow-up vector;
new NIPs and broader runtime features are otherwise out of scope for the
Draft 0.1 conformance freeze unless required to fix an existing vector.
