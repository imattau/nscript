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

## Concord: scoped grants

```nostr
use concord04

key devs = host("devs")

permissions {
    concord Kick in devs
}

kick alice
```

`concord <Verb> in <scope>` (RFC 0002 §2) grants exactly what the flat
`concord_kick`/`concord_ban` permission would — there is no multi-scope
authority host yet for `in devs` to narrow against, so a scoped grant and its
flat equivalent currently behave identically at run time. What the checker
does enforce: the verb must be `Kick` or `Ban` (`E3001` otherwise), and the
scope must be a name the program actually declares — a `key`, `let`, or other
capability (`E1101` for an unknown one). The scope's `in` clause is optional;
`concord Kick` alone is a plain grant of `concord_kick`. This is additive:
existing programs granting the flat `concord_kick`/`concord_ban` names are
unaffected, and a scoped grant can only ever add to a program's capability
set, never widen it beyond what the flat form already could.

Reading a stream did not end up needing new syntax either: `stream messages =
select StreamMessage from chat` and `on messages { }` already parse and check
(see the "Current state" example under [RFC
0002](../rfcs/0002-concord-language-surface.md)'s implementation notes), so no
dedicated `on chat.message { }` keyword was added.

## NIP module sugar beyond Concord

```nostr
use nip02

permissions {
    follow_list
}

follow [alice, bob]
```

`follow <people>` lowers to `nip02.publish_follow_list(FollowList { people:
<people> })`. `<people>` is a list literal; passing a list through a Layer 3
form (and through a module operation generally) works end to end now, not
just scalars and records.

```nostr
use nip23

permissions {
    article
}

article "post-1" titled "My Post" content "Body text"
```

```nostr
use nip29

permissions {
    group_message
}

message "hello" in "general"
```

`message <text> in <group>` lowers to `nip29.publish_group_message`. It is a
distinct keyword from Concord's `say <text> in <stream>`: the two forms lower
to different modules, and the parser cannot tell the two apart from the
argument alone.

```nostr
use nip65

permissions {
    relay_list
}

relays read ["wss://a.example"] write ["wss://b.example"]
```

```nostr
use nip5a

permissions {
    deploy_site
}

deploy "example.com" from "dist/"
```

```nostr
use nip78

permissions {
    app_data
}

save "preferences" as "{\"theme\":\"dark\"}"
```

Every form above follows the same rule as the rest of Layer 3: an incomplete
statement is `E1101`, never a silent no-op, and each keyword is recognised
only at the start of a statement (`let follow = 1` still works).

Not yet sugar, and not planned as sugar: modules that are infrastructure
rather than intents — `nip19` (bech32 encode/decode, called as ordinary
`function`s), `nip42`/`nip46`/`nip98` (auth/signing handshakes), `nip44`/
`nip59` (encryption primitives Concord builds on), `nip45` (a read-only
count query), `nip47` (wallet payment, lower-level than `zap`), `nip77`
(relay sync) and `nip86` (relay admin). These stay `module.operation(...)`
calls; a keyword would not make them more readable.

## Four more NIP modules, deliberately unsugared

`nip88` (polls), `nip92` (media attachment metadata, "imeta"), `nip36`
(sensitive content) and `nip40` (expiration) are typed modules but, unlike
everything above, none of them own a distinct Nostr event kind the way
`nip23`'s article or `nip53`'s live event does:

- NIP-88 defines two real kinds (1068 poll, 1018 response), so `nip88` gets
  two operations, `publish_poll` and `respond_to_poll`, each with its own
  permission (`poll`, `poll_response`).
- NIP-92, NIP-36 and NIP-40 are each a *tag* attachable to any event kind
  (`imeta`, `content-warning`, `expiration`), not a kind of their own. The
  language's core `publish <Event> { ... }` path does not thread arbitrary
  tags today (`nip01`'s `Note.tags` field is read-side only; nothing wires
  a written tag list onto a published event yet), so each of these three is
  scoped honestly to the one case the language already models well: a text
  note carrying that tag. `nip92.publish_note_with_media`,
  `nip36.publish_note_with_warning` and `nip40.publish_expiring_note` each
  take a `content: Text` plus the tag's own fields, and publish a plain
  note. They do not (and cannot yet) attach these tags to an article, a
  poll, or any other event kind — that needs a general tag-carrying publish
  path, which is unbuilt.

```nostr
use nip88

permissions {
    poll
}

let result = nip88.publish_poll(Poll {
    question: "Best relay?";
    options: [
        PollOption { id: "a"; label: "relay.damus.io" },
        PollOption { id: "b"; label: "nos.lol" },
    ];
    multiple_choice: false;
    ends_at: 1700000000;
})
```

```nostr
use nip92

permissions {
    media
}

nip92.publish_note_with_media(NoteWithMedia {
    content: "Check out this photo";
    media: [
        MediaAttachment {
            url: "https://cdn.example/photo.jpg";
            mime: "image/jpeg";
            hash: "sha256:abc123";
        },
    ];
})
```

None of the four get Layer 3 keywords: a poll's shape (a list of option
records, a bool, a timestamp) doesn't compress into a short intent phrase
the way `kick <member>` does, and the other three are exactly the
`module.operation(...)` case the rest of this document already treats as
not worth sugaring.

Building this also closed a real gap: a plain `false`/`true` literal used as
a record field or list element was silently dropped before reaching a
module operation (`ExprKind::Bool` had no `CheckedArgument` case), so
`multiple_choice: false` in a poll vanished from the checked arguments and
the operation failed at run time with a shape error, even though `check`
passed clean. `CheckedArgument::Bool` now carries it through, the same way
`CheckedArgument::List` was added for `follow`/`relays` earlier in this
document.

## Four more: NIP-27, NIP-30, NIP-39, NIP-73

Same honest scoping as the previous four: each of these is, in real Nostr, a
tag attachable to arbitrary event kinds, not a kind of its own, and the
language's core publish path still has no general tag mechanism. Each module
below covers the one case it models well and no more.

- `nip27` (text note references): `nip27.publish_note_with_mentions` takes a
  note's content plus a `List<PubKey>` of mentioned profiles, published as
  `p` tags. It does not build `q` tags for mentioned *events* (NIP-27's other
  half) — that needs an `EventId`/`nevent` reference shape this module
  doesn't take yet.
- `nip30` (custom emoji): `nip30.publish_note_with_emoji` takes content plus
  a list of `CustomEmoji { shortcode, url }`, published as `emoji` tags. The
  spec's optional third tag element (a `kind:pubkey:d-tag` pointer to a
  NIP-51 emoji-set event) is not modelled.
- `nip39` (external identity claims): `nip39.publish_identity_claims`
  publishes one or more `ExternalIdentity { platform, proof }` pairs as `i`
  tags on the claims event. Verifying a proof (fetching the gist, the tweet,
  ...) is out of scope, as it always has been for every other module here —
  the module publishes the claim, it does not check it.
- `nip73` (external content IDs): modelled as a comment whose target is an
  external identifier rather than another Nostr event —
  `nip73.publish_external_comment(ExternalComment { content, target_id,
  target_kind })` — since a comment on an external ID is the NIP's own
  primary example and the shape NIP-22's `Comment` already established here.
  A raw `i`/`k` tag pair on some other event kind is not exposed separately.

None of the four get Layer 3 sugar keywords, for the same reason as `nip88`/
`nip92`/`nip36`/`nip40`: each takes a list-of-records or multi-field shape
that doesn't compress into a short intent phrase.

## Four more: NIP-35, NIP-99, NIP-B0, NIP-C0

Unlike the previous two batches, each of these owns one real, addressable
Nostr kind of its own — no tag-attaches-to-anything scoping caveat needed:

- `nip35` (torrents, kind 2003): `nip35.publish_torrent` takes a title,
  description, the v1 BitTorrent info hash, a `List<TorrentFile { path,
  bytes }>`, and a `List<Text>` of tracker URLs. The spec's optional `i`
  tags (category hierarchies, IMDB/TMDB/anilist IDs) and the separate kind
  2004 torrent-comment event are not modelled.
- `nip99` (classified listings, kind 30402): `nip99.publish_listing` takes
  title, summary, content, location, and a flattened `price_amount`/
  `price_currency` (the spec's optional fourth price element, a recurrence
  frequency like "month", is not modelled, nor are `status`, `t`, `image`
  or `g` tags).
- `nipb0` (web bookmarks, kind 39701): `nipb0.publish_bookmark` takes the
  bookmarked URI, an optional-in-spirit title, and a description.
- `nipc0` (code snippets, kind 1337): `nipc0.publish_snippet` takes the
  code, its language, a name and a description. The spec's `extension`,
  `runtime`, `license`, `dep` and `repo` tags are not modelled.

None get Layer 3 sugar keywords either, for the same multi-field-shape
reason as the rest of this section.

Fitting `nip99.Listing` into `OperationValue` also tripped a real
`clippy::result_large_err` warning across the crate: six `Text` fields make
`Listing` 144 bytes, large enough that carrying it inline made it the
largest arm of every `Result<OperationValue, _>` function's error path
(`Value::Op` → `eval::Stop::Propagate`, in particular). It is boxed
(`OperationValue::Listing(Box<Listing>)`) rather than shrunk, since the
fields are the ones the spec actually asks for.

## Four more: NIP-34, NIP-54, NIP-72, NIP-C7

`nip34` and `nip72` each cover several real Nostr kinds; both are scoped to
the one piece that is small, well-defined, and doesn't need key material or
payment rails, with the rest named honestly as unbuilt:

- `nip34` (git): `nip34.publish_repository` covers only the repository
  announcement (kind 30617) — identifier, name, description, clone and web
  URLs. Repository state (30618), patches (1617), pull requests
  (1618/1619), issues (1621) and their status events (1630-1633) are not
  modelled.
- `nip54` (wiki, kind 30818): `nip54.publish_wiki_article` takes an
  identifier, title, summary and content. Merge requests (kind 818) and
  redirects (kind 30819) are not modelled.
- `nip72` (moderated communities): two operations, matching the two pieces
  of the spec that are actual actions rather than a note shape —
  `publish_community` (kind 34550: identifier, name, description,
  moderator pubkeys) and `approve_post` (kind 4550: which community, which
  post, its author and kind, and the approved event's own JSON). Community
  posts themselves (kind 1111) are not modelled separately; NIP-22's
  `Comment` already covers "a note replying to something" and this NIP
  does not need a second version of that shape.
- `nipc7` (chats, kind 9): `send_chat_message` and
  `reply_to_chat_message` (the latter carrying the parent's event id for
  the `q` tag).

None get Layer 3 sugar keywords, for the same reason as the rest of this
section. `Repository`'s five `Text` fields (120 bytes) landed it right at
the `clippy::result_large_err` threshold once wrapped in `OperationValue`
(the 8-byte discriminant pushes it to exactly 128), so it is boxed the same
way `Listing` was.

## Four more: NIP-64, NIP-7D, NIP-F4, NIP-CC

- `nip64` (chess, kind 64): `nip64.publish_chess_game` takes a single
  `pgn: Text` field. NIP-64's actual and only structural rule is that the
  whole event content is one PGN string — the Seven Tag Roster (`White`,
  `Black`, `Result`, ...) lives *inside* that PGN text as its own header
  syntax, not as separate Nostr tags, so there is nothing else for this
  module to structure without generating PGN text itself, which it does
  not do.
- `nip7d` (forum threads, kind 11): `nip7d.publish_thread` takes a title
  and the opening message. Replies (kind 1111) reuse NIP-22's `Comment`
  shape rather than a second copy of it here.
- `nipf4` (podcasts): `publish_podcast_show` (kind 10154) and
  `publish_podcast_episode` (kind 54) cover the two events that actually
  carry content. Authored-podcast verification (kind 10064, a user
  claiming a podcast keypair) and favourites (kind 10054, a NIP-51 list)
  are not modelled.
- `nipcc` (geocaching): `publish_geocache` (kind 37516) and
  `publish_found_log` (kind 7516) cover listing a cache and logging a
  find. Comment-style logs (kind 1111, again NIP-22's `Comment`), the
  cryptographically signed verification event (kind 7517, which needs the
  cache's own signing key — the same key-material exclusion every other
  module here already has) and curation lists (kind 37517) are not
  modelled.

None get Layer 3 sugar keywords. `GeocacheListing` (five `Text` fields plus
two `Int`s, 136 bytes) was boxed up front this time, having already been
caught twice by the same `clippy::result_large_err` threshold in the
previous two batches (`Listing`, `Repository`).

## Four more: NIP-28, NIP-62, NIP-75, NIP-A4

- `nip28` (public chat): four operations — `create_channel` (kind 40),
  `send_channel_message` (kind 42), `hide_message` (kind 43, client-side
  suppression) and `mute_user` (kind 44). Channel metadata updates (kind
  41) and the reply-threading tags on kind 42 (`e` tagged `"reply"`, plus
  a `p` tag) are not modelled; every message here is a root message.
- `nip62` (request to vanish, kind 62): `request_to_vanish` takes a
  `List<Text>` of relay URLs (or the literal `"ALL_RELAYS"`, which this
  module does not special-case — it is just a string the caller can pass)
  and a reason.
- `nip75` (zap goals, kind 9041): `publish_zap_goal` takes a description,
  the target amount in millisats, the relays to aggregate zaps from, and
  a close timestamp. `image`, `summary`, beneficiary zap tags, and the
  `r`/`a`/`goal` linking tags are not modelled.
- `nipa4` (public messages, kind 24): `publish_public_message` takes
  content and a `List<PubKey>` of recipients. Citation (`q`), reaction/zap
  kind (`k`) and `imeta` tags are not modelled — as the spec itself says,
  there is no thread or chatroom concept here to begin with.

None get Layer 3 sugar keywords, for the same reason as the rest of this
section.

## Four more: NIP-03, NIP-70, NIP-90, NIP-A0

NIP-31 (the `alt` tag) was considered for this batch and dropped: it
explicitly excludes `kind:1` notes ("social clients... can still show
something in case a custom event pops up"), so the "attach this one tag
to a plain note" scoping used for NIP-92/36/40/70 would misrepresent it —
the whole point is a fallback on *non-note* custom kinds, and this
language has no generic mechanism to attach a tag to an arbitrary custom
event yet (see the NIP-92 note above). Left unbuilt rather than modelled
dishonestly.

- `nip03` (OpenTimestamps, kind 1040): `publish_timestamp` takes the
  target event's id and kind, plus the base64 `.ots` proof itself as
  opaque text — the proof's own validity (that it actually resolves to a
  Bitcoin block) is not checked here, same as every other module in this
  document that publishes a claim without verifying it.
- `nip70` (protected events): unlike NIP-31, this one *does* fit the "one
  tag on a plain note" pattern — the `-` tag applies to any event kind but
  carries no data, so `publish_protected_note` is exactly that: a note
  with nothing else attached. The spec's actual mechanism (a relay must
  reject it unless the publisher NIP-42-authenticates as the author) is
  relay-side enforcement, not something this module does.
- `nip90` (data vending machines): `publish_job_request` and
  `publish_job_result` cover the two event shapes that actually carry a
  job (kind 5000-5999 and 6000-6999, checked to be in range). Job
  feedback (kind 7000, status updates) and NIP-04-encrypted params are not
  modelled.
- `nipa0` (voice messages, kinds 1222/1244): `publish_voice_message` and
  `reply_with_voice_message` take an audio URL and duration, rejecting a
  duration outside the spec's 0-60 second range. This is a different
  thing from Concord's CORD-07 (`docs/CONCORD.md`) audio/video work:
  CORD-07 is a live channel's presence/broker-auth protocol, this is a
  single voice-note event with no channel or session behind it.

None get Layer 3 sugar keywords, for the same reason as the rest of this
section.

## Four more: NIP-14, NIP-26, NIP-48, NIP-69

`nip14`, `nip26` and `nip48` all fit the "one tag on a plain note" pattern
(like `nip70`, and unlike the excluded `nip31`): each tag applies to any
event kind in the real spec, but has no conflict with being a plain note,
so each module models "a note carrying that one tag":

- `nip14` (subject tag, kind 1): `publish_note_with_subject` takes content
  and a subject line.
- `nip26` (delegated event signing): `publish_delegated_note` takes
  content, the delegator's pubkey, the conditions query string, and the
  delegation token itself as opaque text. The token is a signature the
  delegator produces off-chain over `nostr:delegation:<delegatee
  pubkey>:<conditions>`; this module accepts it as given and does not
  compute or verify it, the same stance as `nip03`'s OTS proof.
- `nip48` (bridged events): `publish_bridged_note` takes content, the
  source object's id, and the originating protocol name (e.g.
  `activitypub`, `atproto`, `rss`, `web`).
- `nip69` (peer-to-peer orders, kind 38383): `publish_order` takes an
  identifier, order type (checked to be `sell` or `buy`), currency,
  status, amount in sats, fiat amount, payment method, and premium
  percentage. Maker rating, geolocation, network/layer and
  expiration tags are not modelled. This announces a trade order, the
  same as `nip99`'s classified listing does for a sale — it does not move
  funds or settle anything, unlike the payment-rail modules (`nip47`,
  `nip57`) this document deliberately keeps separate from Layer 3 sugar.

None get Layer 3 sugar keywords, for the same reason as the rest of this
section. `P2POrder` (six `Text` fields plus two `Int`s, 160 bytes) was
boxed up front, the fourth time this `clippy::result_large_err` shape has
come up (`Listing`, `Repository`, `GeocacheListing`).
