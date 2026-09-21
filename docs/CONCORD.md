# Concord and external protocol extensibility

Concord is a particularly strong validation target for NScript. Armada is
primarily an interoperability client that consumes Concord alongside NIP-17,
NIP-29, Buzz, encrypted voice/video, and other Nostr protocols. NScript should
target Concord first and use Armada as an interoperability and testing target,
not encode Armada as a core protocol.

```text
Armada / bots / automations / services
                  |
                NScript
          +-------+-------+
          |       |       |
        NIPs    CORDs   Buzz/etc
                  |
                Nostr
```

Concord is an encrypted Discord-style community protocol composed of eight
CORD specifications. Its base model is shared-key encrypted streams carried
over ordinary Nostr relays. CORD-01 private streams, for example, use kind
1059 gift wraps signed by a shared stream key; readers subscribe using the
corresponding stream public key.

## Why Concord fits NScript

NScript already supplies most of the foundational machinery: typed events,
NIP-44/NIP-59-oriented encryption boundaries, signing capabilities,
subscriptions, relay sets, transactional storage, idempotency, timers, and
persistent cursors. The value of a Concord module is therefore not another
SDK wrapper; it is hiding the cryptographic envelope and exposing protocol
intent:

```nostr
use concord01

stream chat = concord.stream(channel_key)

on chat.message as message {
    log(message.author)
    log(message.content)
}

chat.publish {
    content: "Deployment finished"
}
```

CORD-04 is an especially strong demonstration. Roles, grants, ranked
permissions, owner-rooted authority, edition chains, bans, kicks, channel
permissions, conflict resolution, and authority citations are independently
folded by each client. NScript should expose the result as typed authority
queries and capability-checked actions:

```nostr
use concord04

on community.message as msg {
    if msg.content.contains("spam") && community.can(me, Ban, msg.author) {
        community.ban(msg.author)
    }
}
```

An automation can be granted `concord Kick` without being granted role or
community-metadata authority.

The `stream`/`on` and `concord Kick in devs` forms above are aspirational; see
[RFC 0002](../rfcs/0002-concord-language-surface.md) for the proposed generic
language extensions that would support them.

## Module boundary

Concord semantics must remain modules, not compiler primitives:

```text
modules/
  concord01  private streams
  concord02  communities
  concord03  channels
  concord04  roles and authority
  concord05  invites
  concord06  rekeys/refoundings
  concord07  audio/video integration
  concord08  disappearing messages
```

The compiler should only provide the generic typed-module, effect, capability,
and state-fold infrastructure needed by those modules.

## Runtime extensions required

| Capability | Current direction | Concord requirement |
|---|---|---|
| Typed events | strong | required |
| NIP-44/NIP-59 boundaries | present in module model | essential |
| Subscriptions, relay sets | present | essential |
| Stateful storage and signing | present | essential |
| Exact byte preservation | partial | immutable `SignedBytes` |
| ECDH and HKDF | host boundary needed | explicit capability-gated APIs |
| Deterministic folds | generic storage only | reducer/state-fold abstraction |
| Epoch/key rotation | not first-class | shared-secret and epoch types |
| Authority graphs | not first-class | deterministic authority fold |

Concord's rewrapping rules can require byte-identical preservation of signed
plaintext. Add nominal immutable types such as `SignedBytes`, `SealedEvent`,
`SharedSecret`, and `DerivedKey` so parse/modify/serialise cannot silently
invalidate signatures. ECDH, HKDF, and shared-secret operations must be
capability- and permission-gated; raw private keys remain unavailable.

## Staged implementation plan

1. Add `SharedSecret`, `DerivedKey`, and immutable `SignedBytes` types.
2. Add capability-gated ECDH/HKDF/key-derivation host operations.
3. Implement CORD-01 first: stream-key derivation, seal construction,
   kind-1059 wrapping, validation, decryption, and typed `StreamMessage`.
4. Add a deterministic fold/state-reducer primitive with bounded storage and
   replay semantics.
5. Implement CORD-02 and CORD-03 using nominal community, epoch, channel,
   control-plane, chat-plane, and guestbook-plane types.
6. Implement CORD-04 authority/roles and build a constrained moderation bot.
7. Exercise generated and consumed events against Armada as an interop client.
8. Implement CORD-05/06 only after key-management and refounding semantics are
   stable; they are substantially more stateful and cryptographic.
9. Treat CORD-07 primarily as host/service integration rather than core
   language functionality.
10. Implement CORD-08 using the existing timer and expiration machinery.

The target demonstration is a Concord automation with explicit authority:

```nostr
use concord

community devs = concord.open(invite)

permissions {
    read devs.messages
    concord Kick in devs
    concord Ban in devs
}

on devs.message as msg {
    if moderation.spam(msg) {
        devs.ban(msg.author)
    }
}
```

Armada should validate interoperability in both directions: NScript-published
events must be readable by Armada, and Armada-published events must trigger
NScript subscriptions. There should be no initial `armada` core module unless
an Armada-specific wire protocol is identified later.
