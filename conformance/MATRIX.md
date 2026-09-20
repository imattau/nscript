# Conformance coverage matrix

This matrix tracks the minimum corpus required before Draft 0.1 can be promoted
to a release candidate. “Fixture” means a source test; “scenario” means a test
against deterministic host fakes.

| Area | Positive | Negative | Runtime vector |
| --- | --- | --- | --- |
| Nominal Nostr types | `nip19.ns` | `nominal-type.ns` | — |
| Event construction and signing state | `hello-note.ns` | `unsigned-publish.ns` | Signer denial |
| Permission/effect checking | `mentions.ns` | `missing-permission.ns` | Capability denial |
| Publication defaults | `default-publish.ns` | `missing-default-signer.ns`, `missing-default-relays.ns` | Expansion trace planned |
| Hardened-agent profile | `default-publish.ns` | `hardened-secret-key.ns`, `hardened-filesystem.ns` | Transitive dependency denial planned |
| Declarative NIP modules | `modules/valid/nip10.nsm` | `modules/invalid/dynamic-wire-name.nsm` | `vectors/module-descriptors.json` |
| Secret-key isolation | `secret-with-capability.ns` | `secret-without-capability.ns` | Secret redaction |
| Query lowering and bounds | `mentions.ns` | `unbounded-local-filter.ns` | Filter trace planned |
| Pattern exhaustiveness | `exhaustive-match.ns` | `non-exhaustive-match.ns`, `unreachable-pattern.ns` | — |
| At-least-once handlers | `idempotent-handler.ns` | `dispatch_event` runtime test | Duplicate delivery |
| Store transactions | `idempotent-handler.ns` | `dispatch_event_transactional` runtime test | Transaction rollback |
| NIP-19 round trips | `nip19.ns` | Planned | `vectors/nip19.json` |
| NIP-46 validation | `hello-note.ns` | Dedicated signer-provision host test | Signer denial |
| Typed tags | `mentions.ns` | Runtime wire-tags test | Serialization |
| Replaceable events | `replaceable.ns` | `invalid-event-mode.ns` | Tie-break vector planned |
| Timers | `timer.ns` | Planned | Timer overlap |
| HTTP origin policy | Example only | Planned | Redirect denial |
| Partial relay publication | `hello-note.ns` | Runtime partial-publication test | Partial publication |
| Package resolution | Resolver transitive-version tests | Planned | Resolver vector planned |

Rows marked “Planned” are release blockers, not unspecified behaviour.
