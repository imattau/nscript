# Publishing NCC events from a repository

`nscript ncc` publishes Nostr Community Convention events from a repository
whose conventions follow the `NCC-00` layout:

```text
ncc-00/
  README.md              # the exact Markdown published as kind 30050 content
  ncc.json               # document title, status, and optional metadata
  supporting/
    implementation.md    # a kind 30053 supporting document
    implementation.json  # its metadata sidecar
ncc-02/
  README.md
  ncc.json
```

The command constructs the same typed events the `ncc00` `NScript` module
exposes, signs them locally, and publishes them to the relays you name. It does
not read keys or files from a script, so a convention repository needs no
filesystem or shell capability in the language.

It covers all four `NCC-00` event kinds:

| Kind | Event | Source |
|---|---|---|
| 30050 | document | `ncc-XX/README.md` + `ncc.json` |
| 30051 | succession | `nscript ncc succession` |
| 30052 | endorsement | `nscript ncc endorse` |
| 30053 | supporting document | `ncc-XX/supporting/<slug>.md` + `<slug>.json` |

## Document metadata

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

## Supporting documents

Each Markdown file under `ncc-XX/supporting/` needs an adjacent JSON sidecar:

```json
{
  "d": "ncc-00-implementation",
  "title": "NScript implementation notes",
  "status": "published",
  "type": "implementation",
  "lang": "en",
  "topics": ["nostr", "nscript"],
  "authors": ["npub1..."],
  "license": "CC0-1.0",
  "for_event": "event:<optional-document-id>",
  "published_at": 1795814935
}
```

- `for` comes from the parent `ncc-XX` directory.
- `d` defaults to `<ncc-id>-<slug>` when omitted.
- `content` is the exact Markdown.
- `type` must be `guide`, `implementation`, `faq`, `migration`, `examples`, or
  `rationale` when present.
- `published_at` is optional; `--published-at` overrides it.

## Check

```bash
nscript ncc check --all
nscript ncc check ncc-00 ncc-02
nscript ncc check --all --json
```

`check` validates every `ncc.json`, README, supporting Markdown file, and
sidecar without connecting to a relay or reading a key. It is suitable for
pull-request CI.

## Publish documents

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

Use `--supporting` to publish the selected conventions' supporting documents
too:

```bash
nscript ncc publish ncc-00 --supporting --relay ... --signer-key-env ...
```

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

### Publish a succession with a document

`--succession` requires exactly one selected document. After the document is
signed and published, the succession references that new event id:

```bash
nscript ncc publish ncc-00 \
  --succession \
  --succession-reason "Refresh stewardship" \
  --succession-content "Steward acknowledges the refreshed NCC-00." \
  --relay ... --signer-key-env ...
```

## Publish supporting documents only

```bash
nscript ncc support --ncc ncc-00 --relay ... --signer-key-env ...
nscript ncc support --ncc ncc-00 --slug implementation ...
nscript ncc support --all ...
```

## Publish a succession

```bash
nscript ncc succession \
  --ncc ncc-00 \
  --authoritative event:<document-event-id> \
  --steward npub1... \
  --reason "Refresh stewardship" \
  --content "Steward acknowledges the refreshed NCC-00." \
  --relay ... --signer-key-env ...
```

`--authoritative` accepts a bare 64-character event id or `event:<id>`;
`--steward` accepts bare hex, `pubkey:<hex>`, or `npub1...`.

## Publish an endorsement

```bash
nscript ncc endorse \
  --ncc ncc-00 \
  --event event:<document-event-id> \
  --role client \
  --implementation NScript \
  --note "Used internally" \
  --content "Endorsed." \
  --relay ... --signer-key-env ...
```

`--role` is repeatable and must be `author`, `client`, or `user`. `--status`
defaults to `published`.

## Dry run

Every publish command supports `--dry-run` and `--json`:

```bash
nscript ncc publish --all --dry-run
nscript ncc publish --all --supporting --dry-run --json
nscript ncc support --ncc ncc-00 --dry-run --json
nscript ncc succession --ncc ncc-00 --authoritative <event-id> --dry-run --json
nscript ncc endorse --ncc ncc-00 --event <event-id> --dry-run --json
```

`--dry-run` prints the exact kind, tags, content size, and relay targets. It
does not sign or connect. For `publish --succession`, the dry run shows the
succession object with `event:<document-event-id>` as a placeholder because the
signed document id is only known during a real publication.

## GitHub Actions

The NCC repository uses `.github/workflows/ncc-publish.yml` with an `action`
choice:

| Action | Result |
|---|---|
| `document` | publish selected documents, with supporting documents |
| `supporting` | publish supporting documents only |
| `succession` | publish a succession for an explicit event id |
| `endorsement` | publish an endorsement for an explicit event id |
| `all` | publish all documents and supporting documents |

- `ncc-*` tags publish the matching document and its supporting documents.
- `workflow_dispatch` supplies the convention, event ids, roles, content, and
  dry-run choice.
- pull requests run `nscript ncc check --all` only.
- the signing key is the existing `NGIT_NSEC` secret, so NCC events and the
  ngit mirror share one identity.
- `nscript` is installed from a pinned commit.

The workflow never runs for pull requests from forks with repository secrets.

The command is not GitHub-specific. Any environment with `nscript`, the
repository, relay access, and a key in an environment variable can run the same
invocations. An ngit or local release flow can publish the same events after
pushing the matching tag.

## Relationship to the `ncc00` module

`ncc00` remains the language-facing schema. `nscript ncc` is the
repository-facing front end. A drift test compares every builder’s tag set with
the module’s `NccDocument`, `NccSuccession`, `NccEndorsement`, and
`NccSupportingDocument` declarations.

Explicit event ids are required for succession and endorsement in this version.
A later `nscript ncc latest` command can resolve the latest document from
relays; `publish --succession` already auto-references the document it signs in
the same run.
