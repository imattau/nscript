# Layer 3 language surface

Layer 3 expresses Nostr intent directly instead of exposing event JSON or raw
NIP operation arguments.

Currently implemented:

```nostr
on Note where tags.t contains "nscript" {
    let message = event.content
    if message contains "help" {
        print(message)
        return
    }
}

publish Note {
    content: "Hello, Nostr"
} to public with account
```

The compiler lowers these forms into typed subscriptions, publication traces,
signing capabilities, relay effects, and bounded handler execution.

Private messaging sugar is now lowered directly into the typed NIP-17 module:

```nostr
use nip17

permissions {
    private_message
}

send "Hello" to alice
```

Thread replies use the same intent-oriented pattern:

```nostr
use nip10

permissions {
    reply
}

reply "Agreed" to event_target
```

Reposts use a direct intent form as well:

```nostr
use nip18

permissions {
    repost
}

repost event_to_repost
```

Relay-backed search is expressed as intent rather than a raw request record:

```nostr
use nip50

permissions {
    search
}

search Note for "nostr scripting"
```

Reactions are also expressed directly:

```nostr
use nip25

permissions {
    reaction
}

react "👍" to event_to_react
```

Deletion is intentionally phrased as a request, matching NIP-09 semantics:

```nostr
use nip09

permissions {
    deletion
}

delete event_to_delete
```

The runtime publishes a typed deletion request; it does not claim that every
relay will remove the original event.

Comments can target arbitrary event kinds through NIP-22:

```nostr
use nip22

permissions {
    comment
}

comment "A useful comment" on event_target
```

Moderation reports use an explicit category:

```nostr
use nip56

permissions {
    report
}

report event_to_report as "spam"
```

Labels use the `nscript` namespace by default; lower-level code can still call
the typed NIP-32 record when a different namespace is required:

```nostr
use nip32

permissions {
    label
}

label event_to_label as "spam"
```

User presence can be published with a concise status intent:

```nostr
use nip38

permissions {
    status
}

status "working"
```

Drafts use an identifier and content expression:

```nostr
use nip37

permissions {
    draft
}

draft "welcome" with "A draft note"
```

Badges use an identifier and display name; descriptions remain available via
the lower-level typed NIP-58 record:

```nostr
use nip58

permissions {
    badge
}

badge "contributor" as "Contributor"
```

Highlights pair quoted content with its source:

```nostr
use nip84

permissions {
    highlight
}

highlight "Nostr-native scripting" from article_url
```

Trusted assertions name a subject, assertion kind, and value:

```nostr
use nip85

permissions {
    assertion
}

assert alice as "trust" value "high"
```

Calendar events use explicit start/end timestamps and a location:

```nostr
use nip52

permissions {
    calendar
}

calendar "Nostr meetup" from start_time to end_time at "Melbourne"
```

Live events use an identifier, title, and summary:

```nostr
use nip53

permissions {
    live_event
}

live "weekly" titled "Nostr Space" about "Community discussion"
```

Image events pair a media URL with a caption:

```nostr
use nip68

permissions {
    image
}

image photo_url caption "A photo"
```

Video events use the same intent shape:

```nostr
use nip71

permissions {
    video
}

video clip_url caption "A clip"
```

File metadata keeps URL, MIME type, and content hash explicit:

```nostr
use nip94

permissions {
    file_metadata
}

file file_url mime "image/jpeg" hash content_hash
```

Blossom uploads make transport, hash, and size explicit:

```nostr
use nipb7

permissions {
    blossom
}

upload file_url hash content_hash size 1024
```

Application handlers declare the event kind, app identity, and endpoint:

```nostr
use nip89

permissions {
    app_handler
}

handler "1" for "nostr-app" at handler_url
```

Payment intent creation is explicit about its amount:

```nostr
use nip57

permissions {
    zap
}

zap alice amount 1000
```

This creates a typed zap request/payment intent; it does not silently authorize
or execute a payment.

## Concord

Three intent forms lower to the typed Concord modules. They are ordinary
Layer 3 sugar: each becomes a `module.operation(...)` call and keeps the same
permission, effect and capability checks as writing that call by hand.

```nostr
use concord04

permissions {
    concord_kick
}

kick alice
```

`kick <member>` lowers to `concord04.kick_member(<member>)` and
`ban <member>` to `concord04.ban_member(<member>)`. A program granted only
`concord_kick` that writes `ban alice` is rejected with `E3001` at check time.
The permission is the *program's* grant; the host still applies the CORD-04
rule at run time, so the acting identity must hold the permission bit and
strictly outrank its target. A `ban` publishes the Banlist layer only; the
Refounding that cuts read access is a separate step.

```nostr
use concord01

permissions {
    concord_publish
}

say "Deployment finished" in chat
```

`say <text> in <stream>` lowers to
`concord01.publish_message(<stream>, StreamMessage { author: me; content: <text> })`.
`me` is the program's principal, and the host refuses to publish as anyone
else. The text is parsed above the precedence of `in`, so the separator is not
mistaken for a membership test (`say "a" + "b" in chat` says `"a" + "b"`).

An incomplete Layer 3 statement is an error, never a silent no-op: `kick` with
no member, `say "hi"` with no `in <stream>`, `react "x"` with no target and the
like report `E1101`. A statement that vanishes without a diagnostic would let a
script check clean and do nothing, which for moderation is a dangerous failure.
The wrapper that names the form covers every Layer 3 keyword (the
`LAYER3_FORMS` list in the parser), so a new form gets it by adding its keyword
there.

The rule is general, not just for Layer 3. Two parser guarantees back it:

- **A statement that fails must say why.** The item loop reports
  `could not parse the statement starting at ...` whenever a parser gives up
  without a diagnostic, so `let x =`, `x =`, `5 +` and `relayset x =` are errors.
- **A statement ends where its line does.** After a statement the parser
  requires a newline, `;`, the enclosing block's closing `}`, or the end of
  input. Leftover tokens are `unexpected ...` errors rather than extra
  statements, so `kick alice bob` cannot silently kick `alice` and ignore `bob`.
  Several statements on one line need `;`.

The words `kick`, `ban` and `say` are recognised only at the start of a
statement; they remain ordinary names elsewhere (`let ban = 1`).

Not yet sugar: reading a stream (`on chat.message { }`) and scoped grants
(`concord Kick in devs`). Those need the generic mechanisms proposed in
[RFC 0002](../rfcs/0002-concord-language-surface.md), not another keyword.

The next Layer 3 forms are deliberately syntax sugar over existing typed NIP
modules:

```nostr
send "Hello" to alice
reply to event { content: "Agreed" }
repost event
search Note for "nostr"
```

Each form must retain the same permission, effect, and capability checks as its
underlying module call. Layer 3 syntax is therefore an intent-oriented facade,
not a second protocol or an authority bypass.
