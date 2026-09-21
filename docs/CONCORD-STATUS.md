# Concord integration: status write-up

Status as of 2026-09-21, commit range `10a7292..HEAD` (25 commits). This
document records what was built for the Concord tranche of `PLAN.md`, how each
part was verified, what was learned about the specification, and what is not
done. It is a snapshot, not a specification: `docs/CONCORD.md` is the design,
`docs/cord/` holds the vendored CORD specs, and `docs/cord/FINDINGS.md` is the
early gap analysis that drove the rework described below.

## Summary

CORD-01 through CORD-06 and CORD-08 are implemented as pure, tested logic in
`nscript-runtime`, with real cryptography and real event construction in a new
`nscript-host-crypto` crate. The pieces were exercised against a live Concord
community (read, decrypt, verify, fold, post), and the write paths that need
authority (moderation, rekey, Refounding) were proved end to end on a
self-made local community. CORD-07 (audio/video) is not started; the plan
treats it as host/service integration.

252 tests pass across the workspace (one further test is ignored because it
needs network access). `cargo clippy --workspace --all-targets` is clean under
the workspace's pedantic lints.

## What exists

| Spec | Where | What it does |
|---|---|---|
| CORD-01 streams | `runtime/stream.rs`, `host-crypto/stream.rs`, `host-crypto/host.rs` | Seal kinds 20013/20014 fixed per plane; real wrap and seal construction and opening (BIP-340 signed wraps, ephemeral `p`, verbatim plaintext seals); channel/epoch binding check; real `seal_message`, `wrap_stream`, `unwrap_stream`, `open_message` operations |
| CORD-02 communities | `runtime/authority.rs`, `community.rs`, `guestbook.rs` | `community_id` owner commitment; metadata and channel reading; Guestbook join/leave/kick/snapshot fold, one-hour future limit, refounder-only snapshots, Complete Memberlist |
| CORD-03 channels | `runtime/community.rs`, `stream.rs` | Channel metadata (terminal deletion, 64-byte name cap), public-channel keying, `channel`/`epoch` binding |
| CORD-04 roles | `runtime/edition.rs`, `authority.rs`, `wire.rs` | Versioned edition chains with the spec's hash, refuse-downgrade, authority-then-lowest-id tie-break, tracking vs fresh-joiner folds; owner-rooted Roster, frozen permission bits, strict-outrank rule, Banlist, `vac` citations resolved against the current roster |
| CORD-05 invites | `runtime/invite.rs` | Bundle validation (owner self-certification, bounds, expiry), link fragment codec and relay dictionary, `bundle_key`, mergeable Invite List, Registry fold, Direct Invites |
| CORD-06 rekeys | `runtime/rekey.rs`, `host-crypto/rekey.rs`, `host-crypto/refound.rs` | Blob forms (72/104/136 bytes), locators, continuity, chunk assembly, race resolution; real blob building and receiving; Refounding with verbatim Control Plane compaction, key roll, channel rekeys, Guestbook snapshot, ordered idempotent publishing |
| CORD-08 timers | `runtime/expiry.rs` | `message_expiration` field, NIP-40 tag rules and exemptions, enforcement by the signed rumor's own tag, timer notices |
| CORD-07 A/V | not started | Host/service integration per the plan |

Supporting changes:

- **`nscript-host-crypto`** (new crate, RustCrypto): `group_key` derivation
  (HKDF, `scalar_normalize`), NIP-44 v2, BIP-340 Schnorr, OS randomness, a real
  `ConcordKeyHost`, a real `concord01` operation host (including
  `publish_message`), and a real `concord04` moderation host. Kept separate so
  the core runtime stays dependency-light.
- **Module descriptors**: `concord01`, `concord02`, `concord04` under
  `modules/std/`, with conformance programs in ordinary NScript source and a
  negative fixture showing a kick-only bot cannot call `ban_member` (`E3001`).
- **`ModerationHost`** (runtime) and **`ConcordModerationHost`** (host-crypto):
  the program's `OperationPolicy` and the CORD-04 roster rule are two
  independent gates. A fully granted script still cannot ban an equal or the
  owner.
- **Relay host hardening** (`RealRelayHost` / `RealRelayPool`): see Findings.
- **RFC 0002** (`rfcs/0002-concord-language-surface.md`): a draft, not
  implemented, for module-provided stream sources, scoped permissions and fold
  queries. It needs review before any language change.

## How it was verified

Four tiers, in decreasing strength:

1. **Independent test vectors.** NIP-44 v2 passes every case in the official
   `paulmillr/nip44` vector file (conversation keys, message keys, padding,
   encrypt/decrypt, 65,535-byte messages, invalid inputs). BIP-340 passes all 19
   official vectors (8 signing, 19 verification). HKDF passes RFC 5869 case 3
   and agrees with the crypto crate's separate implementation on the
   `concord/grant` and `concord/banlist` coordinates.
2. **A live community.** Against a real community reached from an invite link:
   the bundle was fetched from relays and decrypted with the token-derived key;
   the owner self-certified against the `community_id`; every Control Plane wrap
   opened and verified (BIP-340, NIP-44, plaintext seals, the `concord/control`
   `group_key`) and folded through `AuthorityFold` into the community metadata,
   channels and roles; the public channel's chat was decrypted, including the
   owner's own posts from a different client; and events built by this code
   were accepted by relays and read back and verified. The real
   `unwrap_stream`/`open_message` operations decoded all of the channel's
   events. After the owner granted the interop key a moderator role, the fold
   resolved it to rank 2, permission bits 568 (KICK, BAN, MANAGE_MESSAGES,
   MENTION_EVERYONE), staff: read-only, matching the grant.
3. **Local end-to-end on self-made communities.** Moderation, rekey and
   Refounding need authority the interop identity did not have. Each was proved
   by publishing through the real host into a recording relay, then having an
   independent reader that holds only member-level keys open every wrap and fold
   it with the runtime's own authority and Guestbook code.
4. **Unit tests** for each fold and codec, including rejection cases.

## Findings

About the specification:

- **120 base blobs per rekey event do not fit.** Each event is NIP-44 encrypted
  twice and the wrap layer caps plaintext at 65,535 bytes. By NIP-44's padding
  rules 104-byte blobs overflow at roughly 110 per event and 136-byte blobs at
  roughly 100. Only 72-byte channel blobs fit 120. This is this project's
  arithmetic, not a confirmed defect; worth raising with the Concord authors.
  `build_rekey_events` shrinks the chunk size until the rotation fits; receivers
  accept any chunk count.
- **The invite fragment flag.** The spec names a "stock relay set" flag but not
  its bit. A real link decodes as version 4, flags `0x01`, which confirms the
  assumption made in `invite.rs` (bit 0; the stock set is all four dictionary
  relays).
- **Early rework.** The first CORD-01/02 model was built from a summary and was
  structurally wrong (ad-hoc community events, no seal kinds, epochs as control
  events). It was replaced once the real specs were found at
  `concord-protocol/concord`. The descriptors originally pointed at a URL that
  returns 404.

About this codebase:

- **`wss://` connections panicked.** tungstenite's `rustls-tls-native-roots`
  feature selects no crypto provider. `RealRelayHost` now installs `ring` when
  the host application has not installed a provider. Verified by a real TLS
  handshake (opt-in test).
- **Silent relays hung the program.** Reads had no timeout. They now time out
  after ten seconds.
- **`publish` took the next frame as its answer.** It now waits for the `OK`
  naming its event and ignores notices and other frames.
- **`RealRelayPool::publish` aborted on the first failing relay.** It now
  reports each relay's outcome, so partial publication survives. A live relay
  that never answers exercised this.

## What the live community saw

The community is the owner's own. With the owner's authorization, a throwaway
identity (`11a6ffde…`, key held only in the session scratchpad) joined the
Guestbook and posted five chat events in `#general`: an introduction, an
NScript moderation-bot snippet, a note on CORD-08 expiry, a threaded reply, and
one message sent through the real `publish_message` operation. The community's
timer is 90 days, so each carries an expiration tag on the rumor and the wrap.
Relays accepted them (one relay sometimes never answers) and they read back
through our code. Nothing else was published there. In particular, no
moderation action, edition or Refounding has been run against the live
community; the interop identity now holds a moderator role, and using it on real
members was deliberately not done.

## Not done, and limits

- **Not confirmed in an Armada client.** Everything above was verified by this
  project's own code reading events back from relays. Whether an Armada client
  renders the messages, and how it treats the join, is unconfirmed.
- **Live moderation and Refounding.** Proved only on local communities.
  `ban_member` publishes the Banlist layer only; it does not run the Refounding
  that cuts read access. The pieces exist (`plan_refounding`), but driving one
  from a ban needs the member list, channel keys and recipients supplied.
- **Control Plane through the operation host.** The split signer/read key needs
  two keys, which one `DerivedKey` cannot express, so the real `concord01`
  operations cover single-key planes only. `ConcordModerationHost` writes the
  Control Plane directly instead.
- **`group_key` checked only indirectly.** There are no official vectors for
  it. It is checked by properties, by the HKDF cross-check, and live for the
  `concord/control` and `concord/channel` labels. The `concord/control-signer`
  derivation was never checked against a real implementation (the live run used
  the published `control_pk`, not a derived signer), nor was the rarely taken
  `scalar_normalize` retry branch (about 2^-128).
- **Rekeys and Refoundings never met a real client.** Their formats follow the
  spec, but the only reader was this project's own.
- **Fake hosts remain** in the runtime for deterministic tests; production
  behaviour lives in `nscript-host-crypto`. Author signatures there come from a
  local key standing in for a NIP-46 signer.
- **No Layer 3 sugar for Concord.** Layer 3 (`docs/LAYER3.md`) is the set of
  intent forms the parser recognises and lowers into typed module operations:
  `send "hi" to alice`, `reply`, `repost`, `react`, `search`, `delete`,
  `comment`, `report`, `label`, and the `on Note ... { }` / `publish Note { }`
  forms. Concord has none. It is reachable only as ordinary module calls
  (`concord04.kick_member(alice)`) plus a `permissions` block, and the target
  forms in `docs/CONCORD.md` (`stream`, `on chat.message`,
  `concord Kick in devs`) are aspirational. That is deliberate: this tranche
  paused NIP-sugar expansion, and the plan keeps Concord semantics in modules
  rather than in compiler keywords. The existing Layer 3 forms are
  parser-level keywords, so a Concord equivalent (for example a `kick`
  statement) would be a compiler change, not a module. RFC 0002 proposes the
  generic route instead and awaits review.
- **`can_*` operations** return `Int` 0/1 and declare a `Storage` effect only
  because descriptors currently require an effect and the language has no
  boolean result; the RFC proposes fixing this.
- **CORD-07** is not started.

## Reproducing the checks

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo test -p nscript-runtime -- --ignored real_relay_tls   # needs network
```

The interop tool takes a community's link signer key and invite fragment
(the fragment is a secret; do not commit it):

```sh
cargo run -p nscript-host-crypto --example concord_interop -- \
    read|history|ops|whoami <link_signer_hex> <fragment> [keyfile]
```

`read`, `history`, `ops` and `whoami` are read-only. `post` and `publish` send
messages as the identity in `keyfile`.

## Suggested next steps

1. Look at the live community in an Armada client and report what renders.
2. Review RFC 0002 and decide whether Concord gets Layer 3 sugar, and whether
   it arrives through the generic mechanism in the RFC or as a small set of
   dedicated forms in the style of `send` and `react`.
3. Raise the 120-blob arithmetic with the Concord authors.
4. Decide whether to run a live moderation test using a second throwaway
   identity as the target, and whether to drive a Refounding from a ban.
5. Start CORD-07 as host/service integration, or defer it.
