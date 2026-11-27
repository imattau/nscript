# NScript napplets

NScript can act as the behavior layer of a [NIP-5D](https://github.com/nostr-protocol/nips/pull/2303)
napplet. The applet owns presentation and shell interaction; a checked NScript
program owns the rules. The program never receives the shell's `window.napplet`
namespace, signing keys, relays, or storage.

The first adapter profile is the read-only **lens** profile:

- one or more `on Note` handlers;
- `read Note from public` and `relay public`;
- optional `log` for debugging;
- optional `clock` for `now`;
- `view` for the built-in `lens` presentation module;
- no publishing, signing, storage, schedules, inputs, keys, or third-party
  module operations.

## Decisions, not logs

The `lens` module exposes four operations:

```nostr
use lens

permissions {
    view
}

on Note where tags.p contains me {
    if event.content contains "airdrop" {
        lens.hide("promotion")
    }

    if event.content contains "nostr" {
        lens.label("topic", "nostr")
    }

    if text(event.author) in ["<hex>"] {
        lens.pin("priority contact")
    }

    if len(event.tags) > 12 {
        lens.flag("tag spam")
    }
}
```

The ABI returns a decision list per event. Hide is terminal, labels accumulate,
pin sorts the note first, and flag keeps the note visible with a warning. A
malformed decision is ignored, and an evaluation failure is reported instead of
silently hiding the note.

## Query scoping

The checker only accepts handler predicates it can lower: `author == ...`,
`author == me`, or `tags.<name> contains <literal|me|input>`, joined with `and`.
The adapter turns those predicates into NIP-01 filters for the shell's `outbox`
domain:

| Handler | Derived filter |
| --- | --- |
| `on Note` | `{ kinds: [1] }` — the shell's outbox/following feed |
| `on Note where tags.p contains me` | `{ kinds: [1], "#p": [principal] }` |
| `on Note where tags.t contains "nostr"` | `{ kinds: [1], "#t": ["nostr"] }` |
| `on Note where author == "..."` | `{ kinds: [1], authors: ["..."] }` |

A script that uses `me` requires a shell-user principal. Without one the rule
still checks, but it is not activatable and nothing is fetched.

## Browser ABI

| Operation | Purpose |
| --- | --- |
| `napplet_check` | Check a program and return diagnostics, footprint, filters, scope, and module hash. |
| `napplet_open` | Check and cache a session; returns the same review plus a session id. |
| `napplet_eval` | Evaluate one event against a cached session and return decisions. |
| `napplet_close` | Release a session. |
| `napplet_event` | Stateless evaluation wrapper for tests and tooling. |

Sessions are bounded; the oldest is evicted when the cap is reached.

`nscript run` exercises the same rule without a shell: `lens.hide` and the other
decisions appear as simulated operations, so a rule can be previewed from the
CLI before it is pasted into an applet.

## Capability review

The applet shows the checked footprint, derived filters, required/optional NAP
domains, and diagnostics before activation. `outbox` is required. `identity`
is required when the script declares an identity-backed input and optional
otherwise; `storage` is optional. A missing required domain is an explicit
unavailable state, never a fallback to direct network or storage access.

See [`examples/napplet-lens/`](../examples/napplet-lens/) for the reference
applet and [`npm/nscript-napplet/`](../npm/nscript-napplet/) for the embedding
API.

## Manifest events in scripts

The `nip5d` module models the NIP-5D event layer so a script can publish,
validate, audit, or compare manifests. It does not expose the shell transport:
scripts cannot call `window.napplet`, `postMessage`, `MessagePort`, or any NAP
domain, and they still require explicit `Sign` and `Relay` authority to
publish.

```nostr
use nip5d

on Note {
    let errors = nip5d.manifest_errors(event.kind, event.content, event.tags)

    if len(errors) == 0 {
        print("valid manifest")
    }
}
```

`nip5d.compatible(manifest_tags, shell_tags)` reports whether a shell's `N` set
covers a manifest's `R` set, and `nip5d.missing_domains` names the exact gap.
`nip5d.columns(values)` builds the multi-column values used by `i`, `icon`,
`screenshot`, `preview`, and the source tags. [`spec/nostr.md`](../spec/nostr.md)
documents the event declarations and functions, and the same
`nscript-nip5d` validator backs `nscript napplet build`.

## Viewer lists

A lens can declare an explicit viewer input instead of hand-maintaining a
public-key list:

```nostr
input follows: List<PubKey> from identity.follows
input mutes: List<PubKey> from identity.mutes

permissions {
    read Note from public
    relay public
    view
    identity
}

on Note {
    if event.author in mutes {
        lens.hide("muted author")
    }

    if event.author in follows {
        lens.pin("someone you follow")
    }
}
```

The `from` clause is the capability request: `identity` becomes a required
domain in the review, and `@nscript/napplet` resolves the declared lists
through the shell's `identity` domain (`getFollows`, `getMutes`, `getBlocked`)
before opening the session. Missing data is a clear activation failure, not an
empty list, so a broken identity bridge cannot silently change what a rule
hides or pins.
