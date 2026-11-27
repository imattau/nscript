# Publishing NCC documents from a repository

`nscript ncc` publishes Nostr Community Convention documents from a
repository whose conventions follow the `NCC-00` layout:

```text
ncc-00/
  README.md   # the exact Markdown published as the event content
  ncc.json    # title, status, and optional metadata
ncc-02/
  README.md
  ncc.json
```

The command constructs a typed kind `30050` event with the same fields the
`ncc00` `NScript` module exposes, signs it locally, and publishes it to the
relays you name. It does not read keys or files from a script, so a convention
repository needs no filesystem or shell capability in the language.

## `ncc.json`

```json
{
  "title": "Publishing Nostr Community Conventions on Nostr",
  "summary": "How NCCs are published, discovered, revised, and evolved using Nostr.",
  "status": "published",
  "topics": ["nostr", "conventions", "governance"],
  "lang": "en",
  "version": "1.0.0",
  "license": "MIT",
  "authors": ["npub1..."],
  "supersedes": []
}
```

`title` and `status` are required. `status` must be `draft`, `published`,
`superseded`, or `withdrawn`. Every other field is optional and omitted from
the event when absent. `topics` becomes repeated `t` tags, `authors` repeated
`authors` tags, and `supersedes` repeated `supersedes` tags.

The convention identifier (`d`) comes from the directory name. `README.md`
must be UTF-8 and no larger than the `NCC-00` limit of 256 KiB.

## Check

```bash
nscript ncc check --all
nscript ncc check ncc-00 ncc-02
nscript ncc check --all --json
```

`check` validates every `ncc.json` and README without connecting to a relay or
reading a key. It is suitable for pull-request CI.

## Publish

```bash
nscript ncc publish --all \
  --relay wss://relay.damus.io \
  --relay wss://nos.lol \
  --signer-key-env NCC_PUBLISH_NSEC \
  --require-accepted 1
```

`--signer-key-env` names an environment variable holding either 64 hexadecimal
characters or an `nsec1...` key. The key is read by the host, used to sign in
memory, and never exposed to a script or printed.

`--all` skips `draft` conventions unless `--include-drafts` is passed. Explicit
identifiers and `--tag` publish the named convention even if it is a draft.

A release tag such as `ncc-02-v0.6.0` selects `ncc-02` and overrides its
`version` tag. For a manual single-convention publication, pass
`--version <version>` instead:

```bash
nscript ncc publish ncc-02 \
  --version 0.6.0 \
  --relay wss://relay.damus.io \
  --signer-key-env NCC_PUBLISH_NSEC
```

```bash
nscript ncc publish --tag "$GITHUB_REF_NAME" \
  --relay wss://relay.damus.io \
  --signer-key-env NCC_PUBLISH_NSEC \
  --published-at "$(git log -1 --format=%ct "$GITHUB_REF_NAME")"
```

Passing the tag's commit timestamp makes a retried publication produce the same
event id.

## Dry run

```bash
nscript ncc publish --all --dry-run
nscript ncc publish --all --dry-run --json
```

`--dry-run` prints the exact kind, tags, content size, and relay targets. It
does not sign or connect. Use it to review a new convention or a workflow
change before any event is published.

## GitHub Actions

The NCC repository uses `.github/workflows/ncc-publish.yml`:

- `ncc-*` tags publish the matching convention;
- `workflow_dispatch` can publish one convention or all of them, with an optional dry run;
- the all-conventions dispatch passes `--include-drafts`, because several NCCs are still marked draft;
- pull requests run `nscript ncc check --all` only;
- the signing key comes from `NCC_PUBLISH_NSEC`, falling back to `NGIT_NSEC`;
- `nscript` is installed from a pinned commit.

The workflow never runs for pull requests from forks with repository secrets.

## Relationship to the `ncc00` module

`ncc00` remains the language-facing schema. `nscript ncc` is the
repository-facing front end: it reads the same fields, constructs the same kind
`30050` event, and is covered by a drift test that compares its tag set with the
module's `NccDocument` declaration.

Succession (`30051`), endorsement (`30052`), and supporting-document (`30053`)
events are still published through the `ncc00` module in an NScript program;
`nscript ncc` currently covers document publication only.
