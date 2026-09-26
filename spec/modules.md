# Declarative NIP modules

Status: **Draft 0.1 — normative**

NScript modules use UTF-8 `.nsm` files. They describe protocol types and wire
transformations without executing compiler plugins. The compiler parses a module
into `ModuleDescriptor`; compilation and runtime validation consume that same
descriptor.

## Descriptor

Every module declares a unique name, semantic version, compatible NScript range,
and optional upstream NIP reference. It may import exact or ranged module
versions and export nominal types, records, enums, validators, pure function
signatures, events, tags, host operations, errors, and conformance vectors.

```nostr-module
module nip10 @ 0.1.0
language ">=0.1.0 <0.2.0"
reference "https://github.com/nostr-protocol/nips/blob/master/10.md"

event Note {
    kind: 1
    mode: regular
    content: Text
    tags: List<NoteTag> = []
}

tag ReplyTo {
    wire: "e"
    field id: EventId at 1
    field relay: Option<RelayUrl> at 2
    literal "reply" at 3
    field author: Option<PubKey> at 4
    require id != zero_event_id
}
```

## Validation expressions

`require` expressions use a pure subset of NScript: literals, field access,
comparisons, Boolean operators, arithmetic checked for overflow, `length`,
`matches`, `contains`, and calls to other validators in the same resolved module
graph. They cannot recurse, allocate unbounded collections, perform I/O, read
time, access program values, or call host operations. Evaluation is total and
bounded by descriptor size plus input size.

Validators run when constructing source values and when decoding incoming wire
values. A constructor violation is a compile error when all inputs are constant;
otherwise it returns the declared validation error at runtime.

## Wire lowering

Events declare a fixed kind, storage mode, typed content encoding, and allowed
tag union. Tags declare a fixed wire name and positional fields or literals.
Optional trailing fields may be omitted; skipped optional positions before a
later value lower to the declared empty representation. Each wire position is
assigned exactly once. Dynamic tag names, arbitrary JSON templates, and code
execution are forbidden. A program's own `publish` record lowering (field name
to tag name) is specified in the language document; this section governs the
module-declared tag unions those programs import.

Content encodings are `text`, `bytes-base64`, `json<T>`, or a named encoding
provided declaratively by an imported module. JSON uses UTF-8, rejects duplicate
keys, and follows the field policy of `T`.

## Host operations

A module may declare a host operation signature, its closed effect set, and a
structural permission template. It cannot implement the operation. The runtime
binds the declaration to an approved host interface with the same descriptor
hash. Native and WASM module plugins are not part of Draft 0.1.

## Loading and conflicts

The loader resolves versions, rejects cycles, verifies package hashes when
packaged, and canonicalizes descriptors by UTF-8 name ordering with comments and
insignificant whitespace removed. The SHA-256 descriptor hash identifies the
loaded interface.

Canonical encoding version 3 begins with `NSM`, a zero byte, and version byte
`3`. Counts and UTF-8 byte lengths are unsigned 32-bit big-endian integers;
event kinds and tag positions are unsigned 16-bit big-endian integers. Header
fields and every exported declaration category are sorted by UTF-8 name order.
Record and error fields are sorted by name; operation and validator parameters
retain positional order. Requirements, enum variants, and effects are sorted;
tag slots are sorted by position. Optional values use a zero presence byte when
absent and a one byte followed by the encoded string when present. Event modes
are encoded as regular `0`, replaceable `1`, addressable `2`, and ephemeral `3`.
Every collection includes its count, so concatenated values are unambiguous.
Declared dependency names and normalized requirements are included before
exports. The hash is SHA-256 over these bytes. Version 1 is retained only as a
draft hash identifier and is not emitted for new descriptors. Version 2 remains
readable as a draft identifier but omitted pure callable signatures.

Two modules conflict when they export the same qualified identity, claim an
exclusive event kind incompatibly, or provide different definitions for the
same canonical tag constructor. Conflicts produce `E4003`; source import order
never resolves them.

Pure function signatures declare callable module conversions and constructors;
host operations declare effectful capability calls. The resulting public
interface is:

```text
ModuleDescriptor {
    identity, language_range, dependencies, types, validators, functions, events,
    tags, operations, errors, vectors, canonical_hash
}
```

## Profile interaction

Module types, operations, effects, and permission templates are checked against
the selected runtime profile transitively. A hardened-agent program cannot load
a module that exposes a required forbidden operation merely by leaving that
operation unused when the module declares it as an initialization requirement.
Optional unused exports do not add effects, but references to forbidden
`SecretKey` or `Nsec` types are always rejected in the hardened profile.
