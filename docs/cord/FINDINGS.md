# CORD spec research: gaps and revised plan

Source: <https://github.com/concord-protocol/concord> (copies of `01.md`–`08.md`
and `examples.md` live alongside this file). Read: CORD-01, 02, 03, 04 in full.

## Where the current implementation diverges

| Area | Current code | Spec |
|---|---|---|
| Stream event (CORD-01) | `StreamWrap { kind, stream_pubkey, sealed }` with a fake prefix seal | Kind 1059 wrap signed by the stream key, fixed author, **ephemeral `p` tag**, content NIP-44 encrypted under the self-ECDH stream conversation key. The seal is kind **20013** (encrypted rumor) or **20014** (plaintext, byte-verbatim rumor JSON) |
| Seals | one undifferentiated `SealedEvent` | Two forms, fixed per plane: Control = 20014 plaintext, Chat/Guestbook/rekey = 20013 |
| Key derivation | `derive_stream_key(SharedSecret)` | `group_key(label, secret, id, epoch)`: hkdf seed, scalar normalize, x-only pk. Labels `concord/channel`, `concord/control`, `concord/control-signer`, `concord/guestbook` |
| Write-restricted streams | none | Control Plane splits the signer key (`control_root`) from the read key (`community_root`) |
| CORD-02 community model | `community.rs`: channel create/rename/remove + epoch | Wrong shape. State is **editions** (below), not ad-hoc events. Epoch bumps only on a Rekey (CORD-06), never as a control event. Channels are deleted by `"deleted": true`, not removed |
| Ordering | `(created_at, id)` in `Fold` | `created_at*1000 + ms` tag, then authority, then lower rumor id. Same-version edition conflicts: **authority first, then lowest id** |

## Model the fold must implement (CORD-04 §1–5)

- **Edition** = kind 3308 rumor with tags `vsk` (entity type), `eid` (32-byte
  coordinate), `ev` (version, from 1), `ep` (prev edition hash), `vac`
  (authority citation: grant eid, version, hash). Signed by the actor's real key.
- **Edition hash** = sha256(len64(label) || label || eid || version_be8 ||
  (0x01||prev | 0x00||zero32) || len64(content) || content), label
  `vector-community/v1/edition`, content hashed as verbatim bytes.
- **Fold per entity**: highest version with intact chain; refuse downgrade;
  same-version tie: authorized first, then lowest rumor id. Fresh joiner accepts
  the highest authority-verified head despite a dangling `prev`; a tracking
  client treats it as a gap and fails closed for that entity.
- **Owner root**: owner proven by `community_id = sha256("concord/community" ||
  owner_xonly || owner_salt)`; position 0, supreme, never a Role.
- **Roles**: `{role_id, name<=64B, position u32, permissions decimal-string u64,
  scope, color}`; lower position = higher rank; no Role at position 0; an
  edition may not claim a position at or above its signer's. Max 100 Roles,
  64 per member.
- **Permission bits (frozen)**: 0 MANAGE_ROLES, 1 MANAGE_CHANNELS, 2
  MANAGE_METADATA, 3 KICK, 4 BAN, 5 MANAGE_MESSAGES, 6 CREATE_INVITE, 7 retired,
  8 VIEW_AUDIT_LOG, 9 MENTION_EVERYONE, 11 PIN_MESSAGES, 10/12 reserved. No
  all-powerful bit.
- **Authorization rule**: actor holds the bit AND **strictly** outranks target.
- **Grant**: `{member, role_ids (empty = revoke), control_wrap?}`, honoured only
  if signer outranks every Role handed out. **Banlist**: replace-entire list of
  npubs, signer needs BAN; every event from a banned npub is dropped.
- **Staff** = any of MANAGE_ROLES, MANAGE_CHANNELS, MANAGE_METADATA, BAN,
  CREATE_INVITE, PIN_MESSAGES (plus owner). KICK and MANAGE_MESSAGES are not staff.
- **`vac` citations**: block until the cited grant is synced (coordinate,
  version, hash all match), then resolve against the *current* roster.
- **Removal layers**: Role Removal (Grant strip), Cooperative Kick (Guestbook,
  kind 3309), Cryptographic Removal (Ban + Refounding, CORD-06).
- **Guestbook** (CORD-02 §5): kinds 3306 join/leave, 3309 kick, 3312 snapshot;
  per-npub coalesce, latest wins, entries >1h in the future dropped.
- **Channels** (CORD-03): ChannelMetadata edition `{name, private, deleted?}`;
  messages must carry `["channel", id]` and `["epoch", n]` inside the signed
  rumor and be checked against the key that opened the wrap.

## Consequences for the roadmap

1. The generic `Fold` is a sound base but needs a **versioned-edition layer**
   (entity id, version, prev hash, tie-break by authority then id) rather than
   only `(created_at, id)`.
2. **Replace `community.rs`** with an edition-based reducer for ChannelMetadata
   and Community metadata; drop `EpochAdvanced` (epochs belong to CORD-06).
3. **Rework CORD-01 types**: distinguish seal kinds 20013/20014, add
   `group_key` derivation (HKDF + scalar normalise) to the `ConcordKeyHost`
   contract, ephemeral `p` tag, and byte-verbatim plaintext seals.
4. CORD-04 authority is now specifiable exactly (above); implement it as a
   reducer over Roster + Banlist editions, with the owner derived from
   `community_id`, then the constrained moderation bot.
5. Stage 7 interop can use `examples.md` (JSON for every registered kind) as
   test vectors before touching a live Armada.
