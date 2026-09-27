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

## The first implementation milestone: `nscript concord-run`

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

`nscript concord-run` implements this, **scoped to a single pass**: it
connects, loads the real community authority and channel key, processes the
channel's current message history exactly once, reports what it did, and
exits. It is not a persistent polling loop.

```sh
cargo run -p nscript-cli -- concord-run examples/concord-stream-moderation-bot.ns \
  --community <invite-link-signer-hex>=<invite-link-fragment> \
  --channel general \
  --as <bot-secret-hex-or-keyfile-path> \
  --relay wss://relay.example
```

`--community` takes the invite link's signer public key and its fragment
(everything after `#`), exactly as `concord_interop` takes them, since the
fragment already names the bundle token and its own relays; `--relay` adds
operator-supplied relays to query alongside the fragment's own, satisfying
requirement 1's "relay configuration is an explicit input" independently of
what the invite carries. `--as` is the bot's own secret key, as 64 hex
characters or the path to a keyfile holding them (created, with a freshly
generated secret, on first use, and never printed). The command prints the
checked program's operation policy before it loads anything from a relay
(requirement 3), then the community's authority summary, the resolved channel,
each fetched message's public event id and author (never key bytes, per
requirement 6), and per-message dispatch outcomes, ending with a one-line
summary and exiting.

**Requirement 4, single-pass scope note:** this milestone does not build
interval-refresh logic. A single pass loads the verified authority fold
exactly once, immediately before processing the already-fetched channel
history, so the host's final authorization check for every message in that
pass sees the same, just-verified roles, grants, and bans. That satisfies
requirement 4 for one pass by construction — there is no second, later
dispatch within a run for the fold to go stale against. A persistent
deployment that dispatches new messages as they arrive over time would still
need to refresh the fold on an interval; that is out of scope here and left
for a later milestone (see `ROADMAP.md`).

The library functions behind this — real relay I/O (`connect`, `query`,
`publish`) and community loading (`load_community`, `public_channel`,
`channel_key`) — live in
[`nscript-host-crypto`'s `runner` module](../crates/nscript-host-crypto/src/runner.rs),
behind the crate's `real-hosts` feature (on by default). They are exercised by
unit tests against fixture data (no live relay) and by the `concord-run`
subcommand's own integration tests
([`crates/nscript-cli/tests/cli.rs`](../crates/nscript-cli/tests/cli.rs)),
which check the command's explicit-input validation and its offline failure
paths; none of that test coverage connects to a real relay or a real
community.

Run `concord-run` only in a disposable community first. Confirm the published
Guestbook state using an independent Concord client before treating the
workflow as interoperable — that live verification pass has not been done as
part of building this milestone and is a separate, manual step.

See [`ROADMAP.md`](../ROADMAP.md) for the phase exit criteria and deferred
work.
