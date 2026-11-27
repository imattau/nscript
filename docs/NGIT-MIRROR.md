# ngit mirror

The `Nostr mirror` GitHub Actions workflow keeps the public ngit / NIP-34
repository aligned with the GitHub repository:

- Mirror: [`nostr://npub1khf5amw8mrupe649a5mhkk3d2d8wjj06urz6kwawpftk4f68tjlstdmd3q/relay.ngit.dev/nscript`](https://gitworkshop.dev/npub1khf5amw8mrupe649a5mhkk3d2d8wjj06urz6kwawpftk4f68tjlstdmd3q/relay.ngit.dev/nscript)
- Branch: `main`
- Tags: version tags matching `v*`
- Triggers: pushes to `main`, `v*` tags, and manual dispatch
- Direction: GitHub to ngit; do not make independent changes on the mirror

On each run, the workflow fetches the current GitHub `main`, pushes that commit
to ngit, pushes tags, and verifies that the ngit `main` ref matches the GitHub
commit. A tag-triggered run also mirrors the current `main` head, so it cannot
leave the branch behind the release tag's commit.

## Required setup

Configure the GitHub repository secret `NGIT_NSEC` with the Nostr private key
for the mirror publisher identity (`npub1khf5…`). That identity must already be
authorized to push to the `nscript` repository on `relay.ngit.dev`. The secret
is only made available to the mirror step; it is written to a mode-600
runner-temporary file, used for signing, then removed.

The ngit repository has been initialized under this identity and seeded from
the GitHub refs. Its grasp servers match the other project mirrors:
`relay.ngit.dev`, `git.shakespeare.diy`, and `git.nostrhub.io`. The local Git
checkout has `origin` set to GitHub and `ngit` set to the Nostr mirror.

If the secret is missing, the workflow emits a warning and records that the
mirror was skipped. GitHub pushes and releases continue normally. Once the
workflow file is merged to `main`, a subsequent push to `main` or a `v*` tag
will trigger the sync; it can also be dispatched manually from `main`.

Browse the mirror at
[gitworkshop.dev](https://gitworkshop.dev/npub1khf5amw8mrupe649a5mhkk3d2d8wjj06urz6kwawpftk4f68tjlstdmd3q/relay.ngit.dev/nscript).

## NIP-34 events vs git transport

The mirror moves git refs with `ngit`; it does not publish the repository's
NIP-34 collaboration events. Use [`nscript git`](NIP34.md) to publish a
repository announcement, state snapshot, patches, pull requests, issues, or
status events. The two roles are complementary: `ngit` owns the transport,
`nscript git` owns the events.

## Source of truth

GitHub is the publishing source for this workflow. Do not edit the ngit copy
independently. If refs diverge or the ngit repository already has an unrelated
history, stop and reconcile it deliberately before enabling pushes; the mirror
job does not force-push or rewrite history. Releases are still built and
published by [the release workflow](../.github/workflows/release.yml).
