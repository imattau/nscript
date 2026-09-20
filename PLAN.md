# NScript Language Specification Plan

## Summary

Create a specification-first NScript project for a purpose-built, statically
typed Nostr automation language. The deliverable defines the complete language,
runtime capability model, Nostr interoperability, and a separate signed-package
RFC. The specification is structured so a Rust tree-walk interpreter can follow
it without making further language-design decisions.

## Specification structure

- Maintain a versioned specification suite with an overview, normative
  language/runtime specification, and companion package-distribution RFC.
- Include machine-readable EBNF, canonical source examples, diagnostic
  guidelines, and valid/invalid conformance fixtures.
- Use concise DSL forms such as `event`, `select`, `on`, `publish`, `every`,
  `permissions`, and `store` instead of general-purpose library calls.
- Clearly label normative requirements, implementation-defined behaviour, and
  non-normative rationale.

## Language and runtime contracts

- Specify nominal Nostr types, including `PubKey`, `EventId`, `Signature`,
  `RelayUrl`, `Timestamp`, `Kind`, NIP-19 identifiers, and a privileged
  `SecretKey` type requiring an explicit high-risk capability.
- Define event declarations, typed tags, pattern matching, replaceable events,
  NIP modules, query/filter lowering, streams, handlers, timers, stores, HTTP
  allowlists, relay sets, encryption, and signer handles.
- Represent event state as `Unsigned<E>` and `Signed<E>`; only signed events may
  reach the relay publish interface.
- Infer function effects statically. Program permissions must cover every
  reachable effect.
- Use `Result<T, E>` for recoverable failures, without catchable exceptions.
- Use an implicit asynchronous event loop and at-least-once handler delivery.
- Define deterministic evaluation order, handler isolation, cancellation,
  retries, resource limits, and capability-denial behaviour.
- Standardise host capabilities for relays, signers, encryption, storage, HTTP,
  clock, payment, and filesystem access.

## Nostr and packaging specifications

- Make NIP-01, NIP-19, and NIP-46 normative starter modules, with typed common
  tags.
- Specify exact lowering to ordinary Nostr events, tags, filters, identifiers,
  and remote-signing requests.
- Define extensible, versioned NIP modules without compiler-specific special
  cases.
- Keep signed manifests, semantic versions, dependency locking, author
  identities, hashes, Nostr discovery, and Blossom retrieval in a separate
  normative RFC.

## Conformance and acceptance

- Cover all declarations, expressions, queries, handlers, patterns, and
  manifests with valid and invalid parser fixtures.
- Test nominal typing, signing states, typed tags, pattern exhaustiveness,
  effect inference, and permission rejection.
- Test filter lowering, serialisation, NIP-19 round trips, NIP-46 signing,
  replacement, reconnect duplicates, transactional deduplication, timer overlap,
  HTTP denial, and privileged secret access.
- Include end-to-end examples for queries, publication, mentions, moderation,
  encrypted messaging, monitoring, and constrained agents.

## Defaults

- Rust is the reference implementation language.
- The first executable runtime is a tree-walk interpreter.
- Private keys are unavailable by default; `SecretKey` requires a distinct,
  high-risk permission.
- Distributed packaging is normative but separate from the core language.
- Shell access and unrestricted networking are never implicit capabilities.
