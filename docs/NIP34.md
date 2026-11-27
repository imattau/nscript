# NIP-34 git

`nscript` implements the event surface of
[NIP-34](https://github.com/nostr-protocol/nips/blob/master/34.md): repository
announcements and state, patches, pull requests and their updates, issues,
status events, and the user grasp list. It does **not** implement git object
transport — see [Not implemented](#not-implemented).

Two paths reach relays:

- **`nscript git`** builds, signs, and publishes the events from a repository.
  It is the command for CI and release automation.
- **The `nip34` language module** declares the same events, so a script's
  top-level `publish` runs for real under `nscript deploy`.

## Events

| Event | Kind | `nscript git` command |
|---|---|---|
| Repository announcement | `30617` | `announce` |
| Repository state | `30618` | `state` |
| Patch | `1617` | `patch` |
| Pull request | `1618` | `pr` |
| Pull request update | `1619` | `pr-update` |
| Issue | `1621` | `issue` |
| Status: open | `1630` | `status --status open` |
| Status: applied/merged/resolved | `1631` | `status --status merged` |
| Status: closed | `1632` | `status --status closed` |
| Status: draft | `1633` | `status --status draft` |
| Grasp list | `10317` | `grasp` |

## Common flags

Every publishing command accepts:

```
--relay <wss://url>...        relay to publish to (required unless --dry-run)
--signer-key-env <VAR>        environment variable holding the nsec
--published-at <seconds>      created_at override (defaults to now)
--require-accepted <n>        fail unless n events reach n relays (default 1)
--dry-run                     print the unsigned event, publish nothing
--json                        machine-readable output
```

`--signer-key-env` reads a 64-character hex key or an `nsec1...` value, the
same local-signing model as `nscript ncc`.

## Repository metadata

`announce` and `state` read `nip34.json` from `--repo` (default `.`) when it
exists. Flags override the file; with neither, `--d` defaults to the directory
name.

```json
{
  "identifier": "nscript",
  "name": "NScript",
  "description": "A scripting language for Nostr",
  "web": ["https://github.com/imattau/nscript"],
  "clone": ["https://github.com/imattau/nscript.git"],
  "relays": ["wss://relay.ngit.dev"],
  "maintainers": ["npub1..."],
  "topics": ["nostr", "scripting"],
  "earliest_unique_commit": "0123456789abcdef0123456789abcdef01234567"
}
```

`maintainers` accepts bare hex or `npub1...`.

### Announce a repository

```bash
nscript git announce --repo . \
    --relay wss://relay.damus.io --signer-key-env NGIT_NSEC
```

`--web`, `--clone`, `--relay-tag`, `--maintainer`, `--topic`, `--euc`, and
`--fork` override or extend the file. The announcement's `relays` tag names
where patches and issues should be sent; `--relay` names where this command
publishes.

### Publish repository state

```bash
nscript git state --repo . --d nscript --from-git \
    --relay wss://relay.damus.io --signer-key-env NGIT_NSEC
```

`--from-git` reads `refs/heads/*`, `refs/tags/*`, and `HEAD` from the checkout
with `git for-each-ref` and `git symbolic-ref`. Without it, pass each ref
explicitly:

```bash
nscript git state --d nscript \
    --ref refs/heads/main=0123456789abcdef0123456789abcdef01234567 \
    --head refs/heads/main \
    --relay ... --signer-key-env ...
```

Kind `30618` is addressable, so re-publishing replaces the previous state for
that `d` and author; a stale `--published-at` loses to a newer event.

## Patches, pull requests, and issues

The repository argument is the NIP-34 address, `30617:<pubkey>:<identifier>`.
The repository owner is added as the first `p` recipient automatically; repeat
`--to` to notify anyone else.

```bash
# Patch from git format-patch output
git format-patch -1 --stdout | nscript git patch \
    --repository 30617:<pubkey>:nscript --content-file - \
    --root --commit <commit> --committer "Ada,ada@example.com,1700000000,-300" \
    --relay ... --signer-key-env ...

# Pull request
nscript git pr --repository 30617:<pubkey>:nscript \
    --subject "Add NIP-34" --content "This adds the event builders." \
    --commit <tip> --clone https://example.com/nscript.git \
    --branch-name nip34 --relay ... --signer-key-env ...

# Issue
nscript git issue --repository 30617:<pubkey>:nscript \
    --subject "Dropped tag" --content "The last tag is dropped." --label bug \
    --relay ... --signer-key-env ...
```

`--content-file -` reads stdin.

## Status

```bash
nscript git status --status merged \
    --root-event <root-event-id> \
    --repository 30617:<pubkey>:nscript \
    --revision <accepted-revision-id> \
    --q <applied-patch-id> \
    --merge-commit <merge-commit> \
    --relay ... --signer-key-env ...
```

`open`, `applied`, `merged`, and `resolved` map to the four NIP-34 kinds;
`applied`, `merged`, and `resolved` all select kind `1631`. `--revision`
records an accepted revision; `--q` records applied or merged patches and may
repeat. Merge and applied fields are rejected on a status other than `1631`.

The root event id goes in `--root-event` rather than `--root`, which marks the
first patch in a series.

## Grasp list

```bash
nscript git grasp --grasp wss://relay.ngit.dev --grasp wss://git.shakespeare.diy \
    --relay ... --signer-key-env ...
```

Kind `10317` is replaceable: the latest grasp list from the same author wins.

## Resolve the latest repository

```bash
nscript git latest --d nscript --relay wss://relay.damus.io
nscript git latest --d nscript --kind 30618 --author npub1... --relay ... --json
```

`latest` queries every connected relay, deduplicates, and selects the greatest
`created_at` with the lowest event id as the tie-break. It needs no signing key.

## Language module

`modules/std/nip34/0.1.0.nsm` declares the same event shapes plus:

- typed tags for `r`+`euc`, `refs`, `u`, `committer`, `parent-commit`,
  `commit-pgp-sig`, `branch-name`, `merge-base`, status `e` root/reply markers,
  `q`, `merge-commit`, and `applied-as-commits`;
- pure functions `repository_identifier`, `clone_urls`, `relay_urls`, and
  `status_is_known`;
- the existing `publish_repository` operation, kept as a simulated
  compatibility alias.

A script can publish a repository announcement for real under `deploy`:

```nostr
use nip34
use nip46

signer account = nip46()
relayset public = configured

permissions {
    publish RepositoryAnnouncement to public
    sign RepositoryAnnouncement with account
    relay public
}

publish RepositoryAnnouncement {
    d: "nscript",
    name: ["NScript"],
    clone: ["https://github.com/imattau/nscript.git"],
    relays: ["wss://relay.ngit.dev"],
    euc: [EarliestUniqueCommit { commit: "0123456789abcdef0123456789abcdef01234567" }],
    maintainers: ["<hex pubkey>"],
    web: ["https://github.com/imattau/nscript"],
    description: ["A scripting language for Nostr"],
    u: [],
    t: ["nostr"],
} to public with account
```

Repeated typed tags (`refs`, status `e`/`q`, committers) lower one wire tag per
list element. At top level the elements must be literal records; a handler's
`publish` may compute them.

## Not implemented

NIP-34 does not carry git objects. `nscript git` publishes announcements,
state, and collaboration events; actual clone, fetch, and push still happen
over ordinary git transport or a grasp service.

- No `git-remote-nostr` helper and no grasp server.
- No git object transfer, pack negotiation, or authentication.
- No inline file comments (NIP-34 lists them as a possible future addition).

The `nscript` repository's own mirror is still pushed by `ngit` in
[`.github/workflows/ngit-sync.yml`](../.github/workflows/ngit-sync.yml). See
[`docs/NGIT-MIRROR.md`](NGIT-MIRROR.md): `ngit` moves refs; `nscript git`
publishes events. They are complementary.
