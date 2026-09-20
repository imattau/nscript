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

The Rust front end now parses and statically checks the Draft 0.1 source corpus,
and can emit an inspectable publication IR without contacting relays or keys:

```bash
cargo run -p nscript-cli -- check conformance/valid/default-publish.ns
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

## Repository map

- [`PLAN.md`](PLAN.md) records the approved implementation plan.
- [`spec/`](spec/) contains the normative language and runtime specification.
- [`rfcs/`](rfcs/) contains companion proposals, including package distribution.
- [`conformance/`](conformance/) contains executable examples and negative tests
  for future implementations.
- `crates/` contains the Rust syntax, semantics, IR, and CLI front end.

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
