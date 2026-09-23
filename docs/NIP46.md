# NIP-46: a real remote-signer (bunker) client

`crates/nscript-host-crypto/src/nip46.rs` is a real, tested NIP-46 client:
it actually connects to a relay, actually NIP-44-encrypts and Schnorr-signs
the request/response envelope, and actually talks to whatever is on the
other end of a `bunker://` connection string — which can be a browser
extension running in bunker mode (e.g. nsec.app), a phone app, or any other
NIP-46-compliant remote signer. Nothing about it is simulated.

## What existed before this

The architecture was already there, unused: [`Nip46SignerHost<T>`] validates
a `bunker://`/`nostrconnect://` URI and tracks sessions, delegating the
actual protocol work to a `T: Nip46Transport` — a trait with `provision`
and `sign`. Nothing implemented that trait for real; `nscript run` always
uses `FakeSignerHost` instead, by design (it never touches a network or a
key). The building blocks the real implementation needed already existed
elsewhere: a genuine websocket relay client (`RealRelayHost`, on by default
via the `real-hosts` cargo feature) and real NIP-44 encryption
(`nscript-host-crypto::nip44`).

## What `RealNip46Transport` actually does

1. Parses a `bunker://<remote-signer-pubkey>?relay=...&secret=...` URI.
2. Connects to the first relay in the list that answers.
3. Generates a disposable client keypair (per NIP-46: "doesn't need to be
   communicated to user since it's largely disposable").
4. Sends a NIP-44-encrypted `connect` request (kind 24133, `p`-tagged to the
   remote signer), including the URI's `secret` if it had one.
5. Immediately also calls `get_public_key` — the spec requires this
   ("a client MUST NOT assume `user-pubkey` equals `remote-signer-pubkey`"),
   so the real `user-pubkey` is learned as part of connecting, not left for
   a script to ask for separately (there is no script-facing
   `get_public_key` operation).
6. On `sign`, sends a NIP-44-encrypted `sign_event` request carrying the
   unsigned event template, waits for the reply, and **verifies the
   returned event's own signature** (`crate::stream::verify_event`) before
   handing it back — the remote signer is trusted to hold the key, not to
   have replied honestly.

Every read/write goes through `RealRelayHost`, extended with one new method,
[`RealRelayHost::recv_event`]: `SubscriptionHost::poll` only ever returns
once it has seen `EOSE`, which suits a bounded history query but not
waiting on a reply that does not exist yet when the subscription opens — a
NIP-46 response, in particular, where `EOSE` typically arrives (with an
empty batch) before the remote signer has even seen the request.
`recv_event` reads one frame at a time instead, so a caller can retry within
its own budget (30 seconds, by default, for `RealNip46Transport`).

## What is honestly not covered

- **Only `bunker://`.** The reverse `nostrconnect://` flow — where the
  *client* mints the connection URI (for a browser extension to scan or
  paste in) and the signer replies to it — is not implemented.
- **Only `connect` and `sign_event`** (plus the implicit `get_public_key`
  above). `ping`, `nip04_encrypt`/`nip04_decrypt`, `nip44_encrypt`/
  `nip44_decrypt` (the delegated-crypto methods, not the transport's own
  encryption), `switch_relays`, `logout`, and the `auth_url` OAuth-style
  challenge flow are not implemented.
- **Only the first relay that connects**, not every relay in the URI's
  list. NIP-46 recommends using all of them for redundancy.
- **No discovery.** A remote signer's NIP-05 `nip46` block or NIP-89
  `kind:31990` advertisement is not read; a `bunker://` URI is the only way
  in.
- **`nscript run`/`check`/`test-event` still always use `FakeSignerHost`,
  unconditionally** — that has not changed and will not; it is what makes
  `run` safe to try against an untrusted script. A real deployment goes
  through the separate `nscript deploy` command instead — see
  `docs/DEPLOY.md`.

## A real bug this surfaced: sessions keyed by the wrong thing

`Nip46SignerHost::provision` (the pre-existing `SignerProvisionHost` trait
method) stores each session under `session.provider` — the bunker/
nostrconnect URI itself. But `SignerHost::sign`'s own `signer` argument is
always the *script's capability name* (`sign X with account`, from a
`signer account = nip46()` declaration) — never the URI. Those two strings
never matched, so `Nip46SignerHost` could never actually be driven by a real
script; the one pre-existing test exercising it only worked because it
signed with the literal provider string too (`host.sign(4, event,
&session.provider)`), sidestepping the mismatch rather than exposing it.

`Nip46SignerHost::provision_named(name, provider)` is the fix: it still
validates and provisions the same way, but stores the session under `name`.
`nscript deploy` (below) uses this, not the trait method.

## Test coverage

`crates/nscript-host-crypto/src/nip46.rs`'s own tests include a full
`connect` → `get_public_key` → `sign_event` round trip against an
in-process fake bunker over a real local websocket (the same
`TcpListener`/`tungstenite::accept` pattern `nscript-runtime`'s own
`RealRelayHost` tests use) — the fake bunker uses the *same* real NIP-44
and Schnorr code the client does, so passing proves both sides agree on
the wire format, not just that the client's own code runs without a
protocol partner to disagree with it.

[`Nip46SignerHost<T>`]: ../crates/nscript-runtime/src/lib.rs
[`RealRelayHost::recv_event`]: ../crates/nscript-runtime/src/lib.rs
