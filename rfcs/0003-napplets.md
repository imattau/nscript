# RFC 0003: NScript host integration for napplets

Status: **Prototype implemented; broader adapter remains proposed**  
Authors: NScript contributors  
Created: 2026-11-20

## Summary

Define a host adapter that lets NScript programs run as the behavior layer of a
NIP-5D napplet. NScript remains independent of napplets: its permission checker
describes what a program may request, while the napplet shell decides which
requests are available and approved for a particular applet.

The first product target is an **NScript Lens**: a small mentions/feed napplet
whose HTML/JavaScript owns presentation and shell interaction, while NScript
owns query scoping and presentation decisions. The JavaScript bridge translates
between NScript runtime host operations and the NAP APIs exposed by the shell.
The program never receives signing keys, shell objects, or ambient browser
authority.

This RFC is a design proposal. It does not define new NAP wire messages, a new
NScript syntax, or a new permission system.

## Motivation

NScript already has explicit source permissions, inferred effects, a typed
runtime host boundary, a WASM compiler/editor ABI, a simulator, and a browser
Studio. Napplet shells provide a separate sandbox and capability protocol for
web applications. An adapter can join these systems while preserving their
authority boundaries.

The important separation is:

- NScript permissions are the program's requested authority.
- The generated napplet manifest advertises the host domains the applet needs.
- The shell's policy and user approval are authoritative at runtime.
- The adapter only exposes host operations that the shell actually injected.

The compiler must not treat a declared permission as approval, and a script
embedded by an applet must never gain more authority than that applet.

## Existing implementation seams

- `nscript-semantics::footprint` computes the program's requested permissions
  and inferred effects.
- `nscript-runtime` defines relay, signer, storage, and operation host traits,
  as well as a validated WASM dispatch-host boundary.
- `nscript-wasm` exposes compiler, analysis, manifest, and simulation requests
  over a JSON ABI. It is not itself the full interactive napplet runtime.
- `nscript-ir` emits a WASM artifact and embeds dispatch records for operations
  that a host must mediate.
- Napplet is currently a web projection: the app runs in a sandboxed iframe
  and requests shell capabilities through injected JavaScript APIs.

## Implemented prototype boundary

The first implementation supports one adapter profile: read-only `Note`
handlers with `read Note from public`, `relay public`, optional `log` and
`clock`, `view`, and optional source-backed viewer lists (`identity.follows`,
`identity.mutes`, `identity.blocked`). The shared `nscript-napplet` Rust crate
validates that profile, derives NIP-01 outbox filters from the checked handler
predicates, and maps the profile to the required `outbox` domain. `identity`
becomes required when a script declares an identity-backed input and is
otherwise optional; `storage` is optional.

The browser ABI keeps a bounded cache of checked programs (`napplet_open`,
`napplet_eval`, `napplet_close`), passes the shell-user principal into
evaluation, and returns structured presentation decisions:
`lens.hide(reason)`, `lens.label(name, value)`, `lens.pin(reason)`, and
`lens.flag(reason)`. The reusable `@nscript/napplet` package keeps the shell
namespace outside the script, uses the derived filters for the outbox
query/subscription, and owns the query/subscription lifecycle.

The current browser WASM artifact still does not execute NScript bytecode.
Each event is checked and evaluated through the existing deterministic runtime
simulator, which uses fake hosts and performs no relay, signing, or storage side
effects. Publishing, storage, schedules, inputs, keys, and module operations
other than `lens` are rejected by this adapter profile. The checked program is
cached per session, so the source is not reparsed and rechecked for every event.

These seams suggest a JavaScript bridge first. A direct WASM host-import
projection can be evaluated later without changing NScript source permissions.

## Goals

1. Run an NScript event handler in a napplet while keeping relay and signing
   requests behind the shell.
2. Derive a reviewable set of required NAP domains from checked NScript effects
   and permissions.
3. Fail closed when a required domain is absent, a request is denied, or a
   response is malformed.
4. Keep the adapter separate from the language core and keep the simulator
   useful without a shell.
5. Exercise the packaged artifact with napplet's own conformance tooling.

## Non-goals

- Defining a custom NAP or extending NIP-5D.
- Replacing napplet's identity, ACL, sandbox, or distribution model.
- Letting NScript access `window.napplet`, `postMessage`, DOM APIs, or shell
  transport details directly.
- Treating a NIP-5D manifest's `requires` list as a grant.
- Shipping a general user-script plug-in API in another napplet as the first
  implementation.
- Adding `nscript napplet` CLI commands before the adapter and package format
  have been validated in a reference applet.

## Proposed architecture

```text
NScript source ──check──> checked program + capability footprint
       │                         │
       └──compile──> WASM logic  └──> NIP-5D requires metadata
                              │
                    JS runtime bridge
                              │ NAP calls
                      napplet shell
                 (identity, ACL, signing,
                   relays, storage)
```

The first implementation should use a small TypeScript/JavaScript bridge inside
the napplet artifact. The bridge is responsible for:

1. Loading the NScript artifact under explicit memory and execution limits.
2. Validating the artifact's dispatch records against the checked program
   metadata before exposing callbacks.
3. Mapping only supported runtime operations to currently specified NAP APIs.
4. Validating responses and converting transport failures to stable runtime
   errors.
5. Handling cancellation and subscription teardown when the applet closes or
   the user changes the active feed.

The bridge must not implement signing itself or hold private key material. Any
operation that needs signing is delegated to a shell API that provides that
behavior. Do not infer a one-to-one mapping between an NScript permission and
a NAP domain until the exact NAP operation contract supports it; some domains
may bundle several effects, and some effects may have no suitable NAP yet.

## Permission and manifest relationship

At build time, the checker produces two distinct outputs:

1. **NScript footprint:** typed requested permissions and inferred effects,
   including scope such as event type, relay set, signer, or store where
   available.
2. **Napplet requirements:** the smallest set of NAP domains needed by the
   chosen adapter mapping, plus any configuration metadata required by the
   applet.

The mapping is versioned adapter metadata, not a new source-language
permission. If a program's footprint cannot be implemented by the selected
NAP set, the build must report the unsupported permission/effect and stop.
If the shell does not inject a required domain at runtime, the adapter returns
an unavailable/denied error and performs no fallback network or storage access.

Manifest `requires` metadata is a declaration for shell negotiation and
distribution. It is not evidence that the shell granted the capability.
Runtime grants remain a shell decision and may be narrower than the manifest
advertisement.

## First vertical slice

The reference applet is an **NScript Lens** with these behaviors:

- Derive the shell outbox query from the checked handler predicates: a
  `tags.p contains me` rule asks for mentions, a tag rule asks for that tag, and
  a plain `on Note` uses the shell's outbox/following feed.
- Pass each event to a cached checked NScript handler session.
- Apply the script's local decisions: hide with a reason, label, pin, or flag.
- Render accepted notes, hidden notes (with reasons), labels, pins, and a
  compact audit of scanned/kept/hidden/error counts.
- Let the user replace the rule, then show static analysis, the capability
  footprint, and the exact derived query before activation.
- Keep the slice read-only. Publishing and signing are rejected by the profile;
  the shell still owns relay access, identity, and optional settings storage.
- Package a single-file web artifact with a NIP-5D manifest generated by the
  napplet Vite tooling.
- Run the generated artifact through napplet conformance checks.

The first slice does not accept arbitrary code that bypasses NScript's checker.
A user-provided script must be parsed, checked, and matched against the applet's
allowed capability subset before it runs.

## Phases

### Phase 1: adapter contract and mapping

- Inventory the current NAP domain operations and their stability/maturity.
- Map supported NScript host operations to exact NAP request/response shapes.
- Document missing mappings and unsupported effects.
- Add a mock shell adapter so simulator-style tests can cover allow, deny,
  unavailable domain, malformed response, timeout, and cancellation cases.

### Phase 2: reference napplet

- Create a small web applet that loads the bridge and NScript runtime artifact.
- Demonstrate event subscription, checked filtering, teardown, and UI output.
- Keep all Nostr access shell-mediated.
- Verify the generated artifact with napplet conformance tooling.

### Phase 3: build and manifest integration

- Add a build command only after the reference app proves the packaging model.
- Derive NAP requirements from the selected adapter mapping and checked
  NScript footprint.
- Package source maps/diagnostics for developer builds without including them
  in the published artifact unless explicitly requested.
- Add reproducible build and manifest consistency checks.

The prototype implements `nscript napplet requirements <file.ns>` and
`nscript napplet build <project-directory>`. The first command emits a checked
requirement file with the profile, handler filters and principal tags,
required/optional NAP domains, and the `lens` module hash. The second writes
that file, invokes the Vite build, and checks that the generated NIP-5D
sidecar's required/optional domain tags and artifact hash match the checked
source and built HTML.

### Phase 4: programmable napplet extensions

- Define a small lifecycle and event-handler contract for applets that embed
  user scripts.
- Require an enclosing applet to supply an explicit capability ceiling.
- Intersect the script footprint with that ceiling before activation.
- Add cross-applet intents only through existing intent NAP contracts and
  only when the host approves them.

The `@nscript/napplet` package provides the first embedding API and intersects
the checked `outbox` requirement with the supplied capability ceiling. It is
currently limited to the read-only lens profile (Note reads plus local
hide/label/pin/flag decisions); broader NScript programs and additional NAP
domain mappings remain future work.

### Phase 5: direct WASM projection (optional)

Consider direct WASM imports only if the JavaScript bridge creates a measured
runtime or security problem. Any projection must preserve the same operation
validation, payload limits, denial semantics, and capability ceiling.

## Open questions

1. Which current NAP domain(s) provide event query/subscription and publication
   in the shells targeted by the prototype, and what are their maturity levels?
2. Should a later milestone replace the cached, per-event checked simulation with
   executable WASM lowering once the session path's CPU and latency are
   measured?
3. Should later applets accept source-only scripts, prebuilt artifacts, or both?
4. Which diagnostic and source-map information can safely ship with a public
   applet artifact?
5. Which additional NIP-5D requirements can be safely derived when more NAP
   operation mappings are implemented?

## Acceptance criteria for the first prototype

- An invalid or over-capability NScript program cannot be activated.
- Removing a required shell domain causes a clear unavailable result and no
  direct browser fallback.
- Every NAP envelope emitted by the artifact passes the upstream napplet
  conformance validator.
- A denied publish never triggers a signing or relay side effect.
- Closing/replacing the feed releases its subscription and stops future
  handler invocations.
- The same filtering logic can be exercised in the existing simulator.

## References

- [NScript host capability contract](../spec/host.md)
- [NScript WASM engine decision](../docs/WASM-ENGINE.md)
- [napplet SDK and tooling](https://github.com/napplet/web)
- [napplet conformance package](https://napplet.run/docs/packages/conformance.html)
- [NIP-5D and NAP specifications](https://github.com/nostr-protocol/nips/pull/2303)
