# RFC 0001: Signed NScript packages over Nostr and Blossom

Status: **Draft — normative companion specification**

## Abstract

This RFC defines decentralized discovery and installation of signed NScript
packages. Nostr provides publisher identity and mutable release discovery;
content-addressed storage such as Blossom carries immutable source and compiled
artifacts.

## Package identity and manifest

A package is identified by `(publisher PubKey, name)`. Display names such as
`matt/server-monitor` are aliases and MUST resolve to a public key before trust
decisions are made. A release manifest contains:

- package name and semantic version;
- publisher public key and signature;
- language version range;
- source archive hash and locations;
- optional WASM hash and locations;
- dependency requirements;
- required NIP-module versions;
- declared permissions and inferred effect summary; and
- reproducible-build metadata when available.

The canonical manifest encoding and release event kind will be allocated before
this RFC advances from draft. Implementations MUST reject a manifest whose event
author, embedded publisher, and verified signature do not agree.

## Resolution

`nscript install <reference>` resolves an exact release as follows:

1. resolve the publisher identity and package name;
2. fetch candidate signed release events from configured discovery relays;
3. discard invalid, yanked, incompatible, or untrusted candidates;
4. choose the highest semantic version satisfying all constraints;
5. resolve dependencies recursively and reject cycles or version conflicts;
6. write exact event IDs, versions, hashes, and artifact locations to a lockfile;
7. fetch artifacts and verify every content hash; and
8. display the complete transitive permissions for approval before installation.

Resolution is deterministic for the same trusted event set. Lockfile installs do
not silently upgrade. Mutable tags or location URLs never replace hash checking.

## Artifacts and builds

Source archives are mandatory. Precompiled WASM is optional and treated as a
cache: a host MAY rebuild from source and MUST verify the resulting hash when the
manifest claims reproducibility. Blossom is the preferred blob transport, but
any HTTPS source is acceptable when its origin is permitted and the content hash
matches.

Dependencies are immutable release identities, not ambient local modules.
Standard NIP modules follow the same locking rules even when bundled by a host.

## Trust and revocation

Publisher signatures prove authorship, not safety. Hosts maintain local trust
policy and MUST show permission changes during upgrade. A publisher may issue a
signed yank or compromise notice. Existing lockfiles remain reproducible, but a
host SHOULD block known compromised releases unless explicitly overridden.

Registry aliases, curated indexes, and web-of-trust recommendations are optional
discovery inputs. None can replace publisher signature or content verification.

## Open allocation items

Before stabilization, this RFC must allocate or adopt event kinds for package
releases, yanks, and compromise notices; define canonical manifest encoding; and
publish cross-implementation signature and resolution vectors.
