# NScript Draft 0.1 Release Candidate and Compiler Front-End

## Summary

Finish the security and enforcement model before implementing relay execution.
The next milestone turns the architectural RFC into a testable contract by
defining declarative NIP modules, explicit publication defaults, and a normative
hardened-agent profile. Once those rules and conformance fixtures are complete,
build the Rust parser and static checker against them.

## Specification changes

- Define declarative `.nsm` module schemas with no executable plugins. Schemas
  describe nominal types, events, kinds, replacement modes, typed tags, field
  cardinality, content encoding, validation expressions, wire lowering,
  effects, permissions, compatibility ranges, and test vectors.
- Restrict validation expressions to deterministic, total, bounded operations.
  Loading produces a typed `ModuleDescriptor`; conflicting kinds, exports, or
  tag definitions are compile errors.
- Add source-manifest defaults:

  ```nostr
  defaults {
      signer: account
      relays: public
  }
  ```

  Bare publication expands to these declared defaults before effect and
  permission checking. Missing or ambiguous defaults are compile errors; `to`
  and `with` remain explicit overrides.
- Define `runtime hardened-agent` as a normative profile. It forbids
  `SecretKey`/`Nsec`, filesystem access, process or shell execution, raw sockets,
  native plugins, ambient credentials, and unrestricted HTTP. Origin-scoped
  HTTP, NIP-46 signers, declared relays, bounded storage, clock, and logging
  remain available through explicit permissions.
- Resolve query lowering so OR predicates may share one NIP-01 `REQ`, while
  non-representable conjunctions require separate bounded queries and local
  intersection.
- Specify default resolution, module validation phases, profile enforcement,
  canonical module serialization, and stable diagnostics.

## Conformance and Rust front-end

- Complete the release-blocking matrix with fixtures for module schemas, typed
  tags, NIP violations, NIP-19 failures, NIP-46 validation, secret isolation,
  HTTP policy, timers, replacement ties, relay outcomes, and transactions.
- Prove bare publication succeeds only with declared defaults and inferred
  effects still require matching permissions.
- Add hardened-profile tests rejecting prohibited direct and transitive
  capabilities.
- Create a Rust workspace containing a CLI, syntax layer, and semantic layer.
  Implement source/module lexing, parsing, ASTs, name resolution, nominal types,
  event-state checking, effect inference, permission matching, defaults, and
  hardened-profile validation.
- Make `nscript check <file>` consume the corpus and emit normalized diagnostics.
  Real relay, signer, storage, and WASM execution are excluded from this
  milestone.

## Acceptance criteria

- Every conformance-matrix row has positive, negative, and runtime-vector
  coverage where applicable.
- `nscript check` accepts every valid fixture and rejects every invalid fixture
  with the specified code and primary span.
- Arbitrary NIP rules can be expressed through `.nsm` without compiler changes.
- Bare publication expands only to source-declared authority.
- Hardened-agent programs cannot acquire prohibited authority directly,
  transitively, or through modules.
- Specification checks and Rust tests pass in CI on `main`.

## Subsequent milestones

1. Add the tree-walk interpreter with deterministic fake hosts.
2. Implement real NIP-01 relay and NIP-46 signer adapters.
3. Validate automation scenarios and hostile-script resource limits.
4. Add WASM after interpreter semantics stabilize.
5. Stabilize signed package discovery and Blossom distribution.

## Assumptions

- Draft 0.1 may make breaking syntax changes; no migration is required.
- Standard and third-party NIP modules use the same declarative schema format.
- Direct secret keys remain available only outside the hardened-agent profile.
- The repository remains MIT licensed and Rust is the reference language.
