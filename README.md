# NScript

NScript is a purpose-built, statically typed scripting language for Nostr.
It makes events, filters, relays, signers, permissions, and NIP-defined
behaviour language concepts instead of SDK conventions.

```nostr
use nip01
use nip46

signer account = nip46()
relayset public = configured

permissions {
    read Note
    publish Note
    sign Note with account
    relay public
}

publish Note {
    content: "Hello, Nostr"
} to public with account
```

The project is specification-first. The current milestone defines the language,
runtime contract, Nostr interoperability, and conformance expectations before a
reference interpreter is built.

## Repository map

- [`PLAN.md`](PLAN.md) records the approved implementation plan.
- [`spec/`](spec/) contains the normative language and runtime specification.
- [`rfcs/`](rfcs/) contains companion proposals, including package distribution.
- [`conformance/`](conformance/) contains executable examples and negative tests
  for future implementations.

## Status

NScript is an early design. Syntax and semantics are not stable yet. The first
reference implementation is intended to be a Rust tree-walk interpreter; WASM
is the primary sandbox target after the language semantics have been validated.

## Design principles

1. Nostr is the environment, not a library.
2. Nostr values are nominally typed, even when their wire encodings coincide.
3. Signing and other authority flow through explicit capabilities.
4. Source programs declare permissions; the compiler infers effects.
5. NScript lowers to existing Nostr protocols rather than inventing a new wire
   protocol.

## Contributing

Design changes should begin as an issue or RFC and include conformance examples.
Normative terms such as **MUST**, **SHOULD**, and **MAY** follow RFC 2119 usage.

Run `./scripts/check-spec.sh` before submitting a change. It validates the local
documentation links, JSON vectors, negative-fixture metadata, and whitespace.
