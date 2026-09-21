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
