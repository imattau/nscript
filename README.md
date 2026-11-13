# NScript

NScript is a programming language built just for [Nostr](https://nostr.com).
Instead of wiring together libraries, you describe what you want to happen
(publish a note, reply to a message, moderate a chat) and say up front what the
program is allowed to do.

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

This program says it may read and publish notes, and nothing else. It signs
through a remote signer, so the script never handles your private key.

## Why NScript?

- **Safe by default.** Every program lists the permissions it needs. If it tries
  to do something it didn't declare, it is rejected before it runs.
- **Your keys stay private.** Signing goes through a signer you control. Scripts
  never see raw private keys.
- **Built for Nostr.** Notes, filters, relays and signers are part of the
  language, not add-ons.
- **Nothing new on the wire.** NScript works with the Nostr protocols that
  already exist.

## What you can do with it

- Write bots that reply, moderate, or react to events on Nostr.
- Publish notes, articles, reactions, lists, and other Nostr content.
- Try programs safely in a simulator before connecting to real relays.
- Write and check programs in your browser with the NScript Studio editor in
  [`studio/`](studio/).

## Try it

You will need [Rust](https://www.rust-lang.org/tools/install) installed. From
this folder:

```bash
# Check a program for mistakes
cargo run -p nscript-cli -- check conformance/valid/default-publish.ns

# Run it in the simulator (nothing is sent to the network)
cargo run -p nscript-cli -- run conformance/valid/hello-note.ns
```

More commands, and the technical details of how modules and hosts work, are in
the [compiler, runtime and module reference](docs/COMPILER-RUNTIME-AND-MODULES.md).

For MCP-compatible agents, build and configure the general-purpose NScript
authoring server described in [`docs/MCP.md`](docs/MCP.md). It provides static
checks, permission and effect inspection, and dry event simulation.

## Examples

- [`examples/layer3-bot.ns`](examples/layer3-bot.ns) is a small bot that
  responds to events and publishes notes.
- [`examples/concord-stream-moderation-bot.ns`](examples/concord-stream-moderation-bot.ns)
  is a moderation bot for encrypted group chat. See
  [`docs/CONCORD-BOT.md`](docs/CONCORD-BOT.md) for what works today.
- [`examples/service-operator-bot.ns`](examples/service-operator-bot.ns) shows
  several Nostr community conventions working together.

## Project status

NScript is an early draft (version 0.1). The language, checker, simulator,
browser Studio and a real relay-and-signer workflow all work. Some operations
are still simulated when you deploy, and a few features are not finished yet.
The [detailed status](docs/COMPILER-RUNTIME-AND-MODULES.md#deployment-status-in-detail)
explains exactly which, and [`ROADMAP.md`](ROADMAP.md) lists what comes next.

## Learn more

- [`ROADMAP.md`](ROADMAP.md): current priorities and release plans.
- [`spec/`](spec/): the formal language and runtime specification.
- [`docs/`](docs/): guides for deployment, Concord, signing and packaging.
- [`rfcs/`](rfcs/): proposals, including package distribution.
- [`conformance/`](conformance/): example programs and tests that any
  implementation must pass.
- [`PLAN.md`](PLAN.md): the implementation history and original phase plan.
- [`crates/`](crates/): the Rust source code (compiler, runtime, command-line
  tool, WebAssembly build and editor support).

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
