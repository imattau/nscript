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
runtime contract, Nostr interoperability, and conformance expectations while the
reference interpreter is being built.

The Rust front end now parses and statically checks the Draft 0.1 source corpus,
can emit an inspectable publication IR, and can execute publication effects
against deterministic fake hosts without contacting real relays or keys:

```bash
cargo run -p nscript-cli -- check conformance/valid/default-publish.ns
cargo run -p nscript-cli -- run conformance/valid/hello-note.ns
cargo run -p nscript-cli -- run conformance/valid/nip44-call.ns
cargo run -p nscript-cli -- run conformance/valid/nip17-send.ns
cargo run -p nscript-cli -- compile --emit ir conformance/valid/hello-note.ns
cargo run -p nscript-cli -- module check conformance/modules/valid/nip10.nsm
cargo run -p nscript-cli -- module hash conformance/modules/valid/nip10.nsm
cargo run -p nscript-cli -- module describe conformance/modules/valid/nip10.nsm
```

Additional modules are resolved locally from deterministic
`<root>/<module>/<version>.nsm` layouts:

```bash
cargo run -p nscript-cli -- check -M ./my-modules program.ns
```

The built-in module graph now includes typed NIP-44 encryption, NIP-59 gift
wrapping, and NIP-17 private-message contracts. These modules declare the
protocol types and required effects; host implementations remain capability
bound and are not given raw private keys. Runtime operation dispatch checks an
explicit capability policy before invoking any module host operation, and
checked source calls can now be executed through that boundary.

NIP-19 identifiers also have a pure typed host path: valid `npub`, `nprofile`,
`nevent`, and `naddr` Bech32 values are checksum-verified before becoming
nominal identifier values; `npub` can then convert to a nominal `PubKey`.

NIP-65 relay preferences are represented as a typed `RelayList` and published
through an explicit `Sign`/`Relay` capability operation.

NIP-78 application data is represented as typed addressable `AppData` and
published through the same explicit capability boundary.

NIP-02 follow lists use a typed `FollowList` value and an explicit
`Sign`/`Relay` publication operation.

NIP-25 reactions use a typed `Reaction` value with a nominal target `EventId`
and the same explicit publication boundary.

NIP-09 deletion is modeled as a typed `DeletionRequest`, preserving the fact
that relays may accept or ignore the request.

NIP-51 user lists use a typed `UserList` with nominal `PubKey` members and an
explicit signed publication operation.

NIP-57 zaps produce a typed `PaymentIntent` through an explicit payment effect;
creating a request does not silently authorize a transfer.

## Repository map

- [`PLAN.md`](PLAN.md) records the approved implementation plan.
- [`spec/`](spec/) contains the normative language and runtime specification.
- [`rfcs/`](rfcs/) contains companion proposals, including package distribution.
- [`conformance/`](conformance/) contains executable examples and negative tests
  for future implementations.
- `crates/` contains the Rust syntax, semantics, IR, reference runtime, and CLI front end.

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

## License

NScript is available under the [MIT License](LICENSE).
