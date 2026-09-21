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
