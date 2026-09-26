# NScript specification

Status: **Draft 0.1**

This directory defines NScript's normative source language and host contract.
Unless a section says otherwise, the key words **MUST**, **MUST NOT**, **SHOULD**,
**SHOULD NOT**, and **MAY** are normative.

## Documents

- [`language.md`](language.md): syntax, types, effects, execution, and host APIs.
- [`nostr.md`](nostr.md): event, relay, signer, identifier, and NIP lowering.
- [`host.md`](host.md): portable capability interfaces and failure contracts.
- [`modules.md`](modules.md): declarative NIP-module format and loading rules.
- [`diagnostics.md`](diagnostics.md): stable diagnostic classes and rendering.
- [`grammar.ebnf`](grammar.ebnf): lexical and syntactic grammar.
- [`module-schema.ebnf`](module-schema.ebnf): declarative `.nsm` grammar.

The package ecosystem is specified separately in
[`../rfcs/0001-packages.md`](../rfcs/0001-packages.md).

Protocol interpretations in Draft 0.1 were reviewed against upstream NIPs commit
[`11cca8f6`](https://github.com/nostr-protocol/nips/tree/11cca8f6cf0b65ef4fa6ab97deb2c68db4900847)
from 2026-09-19. A release MUST record a new review commit when updating module
lowering behaviour.

Nostr Community Conventions were reviewed against
[`imattau/nostr-community-conventions`](https://github.com/imattau/nostr-community-conventions)
commit [`71238583`](https://github.com/imattau/nostr-community-conventions/tree/712385839c5cd9d254c765b1fa900d0670a468dc).
Community-convention modules follow the same rule: a release MUST record a new
pin when updating their lowering behaviour. The integration plan lives in
[`../NCC-PLAN.md`](../NCC-PLAN.md).

## Compatibility

An implementation is conforming when it:

1. accepts every valid conformance fixture;
2. rejects every invalid fixture for the documented reason;
3. implements the observable evaluation and host-boundary semantics here; and
4. emits standard Nostr wire data for all defined NIP modules.

Extensions MUST NOT silently change the meaning of conforming source. An
implementation SHOULD expose its language version and supported NIP-module
versions through `nscript --version` and `nscript modules`.
