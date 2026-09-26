# Concord moderation bot: current workflow

[`examples/concord-stream-moderation-bot.ns`](../examples/concord-stream-moderation-bot.ns)
is the intended NScript shape for a moderation bot that reads an encrypted
channel and kicks messages containing `spam`.
The content rule and action are authored in NScript. The Rust interop runner
acts as the host: it fetches relay data, verifies and decrypts Concord wraps,
and provides the capability that publishes an authorized kick.

## Inspect and preview safely

From the repository root:

```sh
cargo run -p nscript-cli -- check examples/concord-stream-moderation-bot.ns
cargo run -p nscript-cli -- inspect --json examples/concord-stream-moderation-bot.ns
cargo run -p nscript-cli -- run examples/concord-stream-moderation-bot.ns \
  --as <bot-pubkey> \
  --event '{"event_type":"StreamMessage","content":"buy spam now","signer":"<author-pubkey>"}'
```

`check` validates the source. `inspect` reports its checked permissions,
operations, subscriptions, and each resolved module's version, canonical hash,
and origin. `run` uses fake hosts: the event is synthetic,
`host("general")` is not connected to a community key, and the kick is only
reported as a simulated operation. These commands do not connect to relays or
publish moderation events.

## What is already exercised against real protocol data

The `nscript-host-crypto` integration test
`a_script_reads_a_real_channel_and_kicks_the_spammer` builds encrypted channel
messages, reads them through `ChannelReader`, evaluates NScript handler code,
and sends the resulting kick through `ConcordModerationHost`. It then opens and
folds the published Guestbook directive independently, confirming that the
spammer was kicked and the innocent author was untouched. The companion test
`the_script_cannot_do_more_than_the_program_was_granted` proves that the
runtime policy blocks the operation before publication when the grant is
removed. These are deterministic local host tests, not a live relay deployment.

The real protocol interop commands in
[`nscript-host-crypto`'s Concord interop example](../crates/nscript-host-crypto/examples/concord_interop.rs)
can inspect a community and channel. They are Rust tooling, not an NScript
bot runner.

## Live deployment status

The generic `nscript deploy` command still simulates module operations. A
does not yet connect this NScript source to the real Concord reader and
moderation host. The protocol logic exists in Rust, and integration tests
exercise the reader → NScript handler → moderation host path with local relay
fakes, but there is not yet a supported live runner that executes this `.ns`
program against a community. The earlier `concord_interop` example is protocol
inspection tooling; it is not a live NScript bot host.

The next host integration should keep policy in this `.ns` file and limit Rust
to provisioning the relay reader, channel key, current authority fold, signer,
and capability adapters. In particular, it must refresh verified authority
before dispatch, stop on incomplete relay reads or key-epoch changes, and
require an explicit operator acknowledgement before publishing kicks. Use a
disposable community and verify the resulting Guestbook state in an independent
Concord client before calling that path interoperable.

The first implementation milestone is a controlled Concord runner that:

1. accepts the program, community/channel selection, bot identity, and relay
   configuration as explicit inputs;
2. loads and verifies the community authority state and channel stream;
3. checks the source and prints its operation policy before starting;
4. refreshes the verified authority fold before dispatch, so role and grant
   changes are reflected in the host's final authorization check;
5. dispatches verified messages to handlers and routes authorized kicks to the
   real moderation host; and
6. records decisions, refusals, and relay outcomes without logging key bytes.

Run that path only in a disposable community first. Confirm the published
Guestbook state using an independent Concord client before treating the
workflow as interoperable.

See [`ROADMAP.md`](../ROADMAP.md) for the phase exit criteria and deferred
work.
