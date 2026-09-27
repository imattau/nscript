# `nscript deploy`: a real execution mode

`nscript check`, `nscript run` and `nscript test-event` never touch a
network or a key — every host is a fake, on purpose, so trying an untrusted
script is always safe. Until now that meant there was no way to actually run
a finished script against real infrastructure through the CLI at all: the
real capabilities that exist in this repo (`RealRelayHost`,
`RealNip46Transport` — see `docs/NIP46.md`) were reachable only by writing
your own Rust binary to drive a `Runtime` by hand.

`nscript deploy` is that missing path.

```
nscript deploy [-M <directory>]... <file> \
    --relay <wss://url>... \
    [--signer <name>=<bunker://...>]... \
    [--as <key>] [--poll-interval <seconds>] [--cycles <n>]
```

Each `--relay` is either a concrete websocket URL or an identity reference
(`wss://npub…`) that resolves to one — see “Identity references” below.

## What is real

- **Relays.** Every `--relay` is a genuine websocket connection
  (`RealRelayPool`). The program's own top-level `publish` runs immediately,
  for real, exactly like `nscript run` does — except it actually reaches a
  relay this time.
- **Signing.** Each `--signer <name>=<bunker://...>` provisions a real
  NIP-46 session (`Nip46SignerHost::provision_named`, see `docs/NIP46.md`)
  before anything else runs; a script's `signer <name> = nip46()` then
  resolves to that real remote signer — which may be a browser extension
  running in bunker mode, a phone app, or any other compliant signer.
- **The event loop.** After the startup publish, `deploy` subscribes to
  every declared handler's filter, dispatches whatever is delivered through
  the same idempotent, transactional path `dispatch_evaluated` already gives
  `test-event`, unsubscribes, sleeps `--poll-interval` seconds (5 by
  default), and repeats — until `--cycles` is reached or the process is
  interrupted. `run`'s `--event`/`--events` are one-shot by design; this is
  the genuine "keep watching" loop those were never meant to be.

## Identity references (`wss://npub…`)

`--relay` also accepts an identity reference — a URL whose authority is an
`npub`, NCC-06 §Scope — which is never connected to directly: such a URL
names a key, not a socket. Before anything publishes, `deploy` resolves it
under the profile:

1. **Bootstrap.** At least one *concrete* `--relay` must stand in for the
   identity's publication relay set (§C.2). With none, deploy refuses
   (exit 2) rather than guessing an endpoint.
2. **Query (§C.2).** Each concrete relay is asked for the identity's NCC-02
   Service Records and NCC-05 Locators — kinds 30059 and 30058, filtered by
   the decoded pubkey — through one bounded subscription: §A is owed only
   the newest candidates, not a flood.
3. **Discard (§A step 1).** Candidates are rejected in order of cheapest
   check: wrong author, wrong kind, an event id that does not recompute over
   this body, a signature that does not verify, then duplicates.
4. **Select (§A).** Usable beats unusable, the greater freshness marker
   wins (`created_at` for service records; the locator's `updated_at`, else
   its `created_at`), and an exact tie falls to the lexicographically
   greatest event id — two relays holding the same candidates settle on the
   same record.
5. **Walk (§E.1).** The endpoint comes from the selected locator's payload,
   regrouped into §E.1's tiers (secure with `k`, secure without, onion,
   insecure), never from an endpoint that is itself an identity reference —
   §Scope does not recurse — falling back to the service record's `u` when
   no usable locator offers one.
6. **Report.** What was selected is printed: candidate count, the short ids
   of both records, the endpoint with its source and §E.1 rank, and the `k`
   the record pinned **with `verified: no`** — TLS key pinning (§E.2) is not
   implemented, and a printed key must not imply one was checked. The
   endpoint then joins the pool and the deploy continues through it.

A resolution that finds no usable endpoint fails the deploy (exit 1) with
the reason — no records answered, none usable at this clock, or no concrete
endpoint anywhere — instead of connecting to something. §D.3's stale
fallback is absent for the same reason `run`'s fakes keep no state:
`deploy` caches nothing, so there is no previously valid record to fall
back on, and the error says exactly that.

## What is still simulated, on purpose

**Module operation calls stay simulated.** `kick`, `react`,
`nip56.publish_report(...)`, and every one of the other ~75 NIPs' typed
operations still go through the same simulator `run`/`test-event` use.
Making every module operation real would mean building a real host
implementation for each one individually (most reduce to "publish an event
with these exact tags," which needs the module-declared typed tag shapes —
`publish_now` now lowers plain written fields to wire tags, but not algebraic
tag values or positional wire fields, and each operation would still need a
real host implementation) — a much larger, separate effort than wiring up
the relay/signer/event-loop path this command closes. `deploy` prints a
one-line reminder of this whenever a program makes any such call, so it is
never a silent surprise.

## A real bug this closed along the way

Two, actually, both caught by `deploy`'s own end-to-end test, not found by
inspection:

1. **`RealRelayHost::parse_event` cannot know a handler's event-type name**
   (it has no module graph, just a raw wire event), so it always reports a
   delivered event's `event_type` as the literal string `"Event"`.
   `matches_subscription`'s very first check compares that against the
   handler's real name (e.g. `"Note"`), so every real relay-delivered event
   would have been silently rejected before this fix, filter or no filter.
   `deploy` is the one place with both a resolved module graph and the
   handler being polled, so it resolves each handler's event type to its
   real Nostr kind (`event_kind`, the same lookup `nscript-ir` already uses
   for the publish side) and corrects the delivered event's `event_type`
   before dispatch — filtering defensively on the numeric kind first, in
   case a relay ignores the subscription filter.
2. **`Nip46SignerHost` sessions keyed by the wrong string** — see
   `docs/NIP46.md`'s own section on this; `provision_named` is the fix
   `deploy` uses.

## What is not covered

- No `since` cursor: each cycle re-subscribes and a relay may redeliver its
  whole matching history every time. Idempotency (keyed by handler and
  event id) is what keeps that safe — a redelivered event is claimed and
  skipped, not re-run — at the cost of relay traffic a cursor would avoid.
- `every`/`at` (scheduled, not event-triggered handlers) are registered
  (`Runtime::schedule_program`) but not run; `deploy` prints a note for each
  one it sees, the same honesty `run` already has for this.
- One relay pool serves every `relayset` a program declares; there is no
  way to route different relayset names to different sets of relay
  endpoints. `RealRelayPool` is keyed by relay URL, not by relayset name,
  and falls back to broadcasting across every connected relay whenever a
  name does not literally match a URL — which, for `deploy`, is always
  (script relaysets are names like `public`, never URLs).

## Test coverage

`crates/nscript-cli/tests/cli.rs`'s `deploy_with_real_hosts` module runs the
actual `nscript` binary against an in-process fake relay *and* fake bunker,
both real websockets, both using the same real NIP-44/Schnorr code the
client does. It proves the whole chain: connect, provision a real signer,
publish a real signed startup note, receive a real live event over a real
subscription, dispatch the handler, and publish a real signed reply — not
just that each piece works in isolation. A third test drives the identity
path end to end: a bootstrap relay answers the §C.2 record query with real
signed NCC-02/NCC-05 events, the resolver selects under §A, and the
startup publish reaches the resolved endpoint — never the reference.
