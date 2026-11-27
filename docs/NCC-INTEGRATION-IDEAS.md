# NScript as a Programmable Nostr Application Layer

## Purpose and status

This document consolidates architecture and feasibility ideas for connecting NScript with Nostr Navigator, napplets, nsites, Nostr Community Conventions (NCC), and the wider Nostr service ecosystem. It is a design proposal, not a claim that every described integration is implemented.

The repo already has useful foundations: a typed NScript language and runtime, a browser Studio, simulation, NCC modules and repository tooling, NIP-5D manifest support, and a read-only NScript napplet lens profile. The current napplet integration is deliberately narrow. It does not yet imply a general-purpose live WASM execution engine, broad NAP bindings, persistent background workers, or distributed execution.

Use the existing implementation documentation for current behavior: [NCC publishing](NCC.md), [napplets](NAPPLETS.md), [compiler, runtime and modules](COMPILER-RUNTIME-AND-MODULES.md), and [npack](NPACK.md). Treat the roadmap below as proposed work until confirmed in code and conformance coverage.

## Executive summary

The strongest near-term direction is to make NScript a typed behavior and orchestration layer that can run across compatible Nostr application hosts. Host capabilities should be expressed through explicit, typed contracts and mediated by the host. Nostr Navigator can serve as a reference host, while the language and its application logic remain useful to other shells and native environments.

The technologies answer different questions:

| Component | Main responsibility |
| --- | --- |
| Nostr | Identity, signed messages, and interoperable event data |
| NCC | Convention documents and, where applicable, service discovery and trust metadata |
| Napplet / NAP | Portable application packaging and host-provided capabilities |
| NScript | Typed rules, event handling, permissions, and application workflows |
| Nsite | Signed web application distribution through content-addressed assets |
| npack | Distribution of standalone NScript programs, modules, and related runtime artifacts |
| Navigator | An integrated user-facing host that can broker capabilities and compose applications |

Keep these boundaries explicit. Discovery does not grant access; a signed event does not guarantee delivery, confidentiality, ordering, or exactly-once processing; and a declaration in a script is not a substitute for enforcement by the host.

## Existing foundations and gaps

### Foundations present in this repository

- NScript has typed Nostr concepts, explicit permission declarations, a compiler/checker, runtime and simulator.
- NCC modules expose convention-specific parsing and validation functions. `nscript ncc` checks and publishes NCC documents from repository layouts.
- NIP-5D manifest support validates and builds napplet artifacts and manifest-related data.
- `npm/nscript-napplet` and the reference lens applet connect a restricted NScript profile to a browser embedding API.
- The lens profile supports checked event rules and local hide, label, pin, and flag decisions, with derived query filters and explicit capability review.
- The repository includes a WASM engine and Studio; their existence should not be confused with a complete browser-hosted, asynchronous NAP runtime.

### Main integration gaps

- A general live execution adapter must bridge NScript operations to host capabilities while preserving permission checks and asynchronous lifecycle behavior.
- NAP capability contracts need typed NScript bindings and conformance coverage. The adapter should reuse existing NAP domains instead of inventing parallel language-specific capability protocols.
- Browser signing, relay access, identity, storage, intents, inter-application communication, and NCC services need host-mediated implementations with clear unavailable states.
- Long-running automation needs a separately authorized host-managed worker lifecycle. It cannot safely depend on an applet frame remaining alive.
- Cross-host portability requires stable capability semantics, version negotiation, error handling, resource limits, and test fixtures.

## Feasibility assessment

These ratings are engineering judgments, not measurements of completion. “High” means the design fits existing abstractions and has a credible implementation path; it does not mean the feature is already shipped.

| Proposal | Feasibility | Main work or constraint |
| --- | --- | --- |
| NScript rules in a napplet | High | Extend the constrained profile carefully; current lens profile is a starting point. |
| Typed NScript bindings to NAP contracts | High | Map existing domains and message schemas; host remains the enforcement boundary. |
| Navigator as a reference napplet host | High | Integrate capability broker and lifecycle with the existing shell architecture. |
| NCC-aware service monitoring | High | Reuse NCC modules and expose narrowly scoped host services where needed. |
| Nsite with local NScript/WASM logic | High | Package runtime assets and implement browser adapters; ordinary gateways only serve files. |
| Persistent desktop workers | Medium | Requires a distinct worker manager, consent, limits, revocation, durable state, and audit. |
| Standalone package integration | Medium | Useful for reusable modules and native programs; avoid requiring npack for normal napplet installs. |
| Remote execution | Medium | Needs a protocol for authorization, operator trust, job lifecycle, and result verification. |
| Always-on Android execution | Medium–low | Constrained by platform background execution and battery policies. |
| Distributed execution mesh | Low to medium | Requires durable coordination, retries, idempotency, checkpoints, trust and dispute handling. |

## Napplet and NAP integration

### Treat NScript as a language binding over NAP

The preferred starting point is not a new NScript-only capability protocol. Expose existing NAP contracts through typed NScript modules and a host adapter. A JavaScript napplet and an NScript program should request the same underlying capabilities and receive the same authorization decisions.

The adapter should:

1. Check the source and derive the required capabilities before activation.
2. Present the capability footprint, filters, identity requirements, and diagnostics to the user.
3. Translate checked operations to host-provided NAP calls.
4. Reject operations outside the declared and granted footprint.
5. Surface unsupported domains and host failures explicitly; never silently fall back to direct network or storage access.
6. Apply resource limits and emit an auditable record of capability use.

Relevant domains may include relay/outbox, identity, storage, intents, inter-application communication, common Nostr operations, upload, filesystem, and language model requests. Their availability and maturity vary by host; the adapter must negotiate and report actual support.

### Foreground and background execution

A foreground napplet is a good first target. Its lifecycle is visible to the user and can be closed by the shell. Persistent tasks should be a separate host-managed service with its own authorization and controls:

- explicit owner and program version;
- separate requested and granted capabilities;
- start, stop, status, and revoke operations;
- resource, frequency, and data-retention limits;
- durable state and restart semantics;
- event and action audit trail;
- behavior when identity, signer, relay, or required service is unavailable.

Do not automatically inherit foreground permissions into a background process. Desktop workers are a more practical initial target than uninterrupted mobile execution.

### NCC integration

NScript can provide typed parsing, validation, freshness checks, and policy logic over NCC records. A host may expose service discovery to applets through a brokered capability. Keep these steps distinct:

1. Discover candidate records or endpoints.
2. Validate structure, signature, freshness, and applicable convention rules.
3. Evaluate operator identity and trust policy.
4. Request permission to connect or invoke the selected service.
5. Apply timeout, budget, data-sharing, and result-validation policy.

A discovered or valid endpoint is not automatically trusted or authorized. Trust decisions need an explicit policy and provenance, and should be reviewable by the user or application owner.

## Nsites and browser execution

Nsites can distribute HTML, JavaScript, NScript source, and a WASM runtime as signed manifest entries backed by content-addressed assets. With client-side execution, the gateway only serves files; it need not run NScript or change the site manifest protocol.

A browser application can use JavaScript for DOM and browser integration while placing Nostr-specific business rules, event handlers, and permission declarations in NScript. A browser host adapter would connect those operations to browser signers (for example, NIP-07 where available), relays, local storage, and any other explicitly granted browser capability.

A shared application could target several hosts:

| Capability | Nsite in browser | Napplet in shell | Native host |
| --- | --- | --- | --- |
| Interface | Web UI | Applet UI | Optional UI |
| NScript execution | Browser/WASM adapter | NAP-aware adapter | Native runtime |
| Signing | Browser signer or remote signer | Shell broker | Configured host signer |
| Relay access | Browser adapter | Shell broker | Native module/host |
| Storage | Browser-managed and origin-scoped | NAP storage domain | Host storage |
| Cross-app calls | Browser-specific adapter | NAP intents/communication | Host operations |
| Background work | Limited and browser-controlled | Separate shell worker | Host-managed service |
| NCC discovery | Browser-side implementation or broker | Shell capability | Native module or host |

The same source does not guarantee identical behavior: hosts have different capabilities, permission prompts, storage boundaries, and lifecycle constraints. Define a portable core and make optional capabilities visible during build and activation.

### Dynamic applications and server-side execution

Nostr events can act as application data, Blossom can hold content-addressed assets, and locally running NScript can process application rules. This can support dynamic community portals, moderation tools, project workflows, marketplaces, and dashboards without a conventional application server for every use case. Relays, storage, identity, and external services still remain dependencies.

A server-side NScript gateway is a separate, higher-risk extension. It could map routes or schedules to programs, but ordinary nsite gateways should never execute arbitrary published code by default. If explored, server-side execution needs explicit operator opt-in, tenant isolation, authenticated input, capability grants, quotas, secrets handling, logging, and abuse controls. Prefer first proving client-side execution and a separately operated worker service.

NScript may also automate publication pipelines: validate an nsite's assets, verify a release, publish or update the signed manifest, and coordinate rollback. This builds on existing publishing and packaging foundations but still needs a well-defined deployment host and credential policy.

## Reference proof of concept: NCC Service Monitor

Start with a read-only foreground napplet that uses NScript to validate service announcements, compare state records, and generate local status or notification decisions. The UI lets a user select services and inspect why a record was accepted or rejected. The first version should not sign transactions, publish events, or invoke discovered endpoints.

A subsequent milestone can add explicit user-approved service invocation. Only after the foreground flow is reliable should a separate desktop worker add subscriptions or scheduled checks.

This proof of concept tests the most valuable boundary: typed NScript logic using host capabilities without bypassing shell policy. It is smaller and more informative than starting with payments, autonomous agents, or remote execution.

### Illustrative NScript logic

The following is adapted from patterns present in the repository's NCC examples. Treat it as illustrative until checked against the current compiler and fixtures:

```nostr
use ncc02
use ncc05
use ncc10

relayset public = configured

permissions {
    read ServiceRecord from public
    read Locator from public
    read ServiceState from public
    relay public
    log
}

on ServiceRecord {
    if ncc02.record_is_valid(event.tags, event.created_at) {
        print("Service endpoint: " + ncc02.endpoint(event.tags))
    }
}

on Locator {
    if not ncc05.record_is_fresh(event.tags, event.content, event.created_at) {
        print("Locator rejected")
        return
    }

    let endpoints = ncc05.payload_endpoints(event.content)
    print("Discovered endpoints: " + text(endpoints))
}

on ServiceState {
    let state = ncc10.state(event.tags)

    if ncc10.state_is_recognised(state) {
        print("Reported service state: " + state)
    }
}
```

This observes and validates event data. It does not prove that a publisher is authorized to speak for a service, establish endpoint trust, or make a network request. Production logic must add those policy checks using available, trustworthy inputs.

## Larger application example: Release Control

A more complete application could coordinate software release review inside a Navigator workspace. The foreground napplet presents candidate versions and an audit trail. NScript evaluates release metadata and deterministic policy. A human approves consequential actions. Host services perform signing, package retrieval, tests, and deployment only after separate permissions and approvals.

The workflow might be:

1. Observe signed release announcements and identify candidates using version rules.
2. Validate publisher identity and authority for the named application.
3. Resolve dependencies and service endpoints through approved NCC policy.
4. Fetch artifacts through a verified package mechanism and check hashes/signatures.
5. Run bounded tests in an isolated environment.
6. Collect required independent approvals.
7. Request explicit deployment authorization, then invoke a deployment capability.
8. Record decision inputs, approvals, artifact identity, and outcome for audit.

Keep discovery and evaluation read-only at first. Do not place secrets in the program or treat script-level conditions as a security boundary. The host and deployment service must enforce approvals and permissions.

## Long-term direction: programmable organizations and service fabric

At the ambitious end, Navigator could compose independently developed applications and services, while NScript coordinates deterministic workflows and AI-assisted tasks. Example applications include project management, development, infrastructure, finance, governance, communication, security, package management, and service marketplaces.

A distributed execution mesh could discover workers through NCC and place jobs based on supported runtime versions, operator policy, trust, location, cost, and available resources. It could support retries, resumable checkpoints, redundancy, and result checks. NCC can help describe and discover services; it does not supply the job protocol, durable scheduler, payment settlement, consensus, or result verification. Each of those needs separate contracts and threat analysis.

Potential organizational policies include spending thresholds, release approval requirements, credential delegation, data retention, and service selection. Enforce such policies at the capability broker and service boundary, with independent authorization and audit. An untrusted program must not be able to grant itself authority by evaluating its own policy.

AI agents can propose plans, generate code, and call tools, while NScript expresses typed deterministic rules and required capabilities. Generated programs should pass static checks, simulation, review, and user authorization before activation. AI output is not an authority source.

This direction is best understood as a programmable application and service fabric, not a feature set already delivered by the current repository.

## Distribution and developer experience

Keep napplet packaging and standalone package distribution complementary:

| Artifact | Likely distribution path |
| --- | --- |
| Napplet application | NIP-5D manifest and its supported artifact flow |
| NScript bundled with an applet | Included in the applet artifact, subject to host profile |
| Standalone NScript program or reusable module | npack, where appropriate |
| Runtime or native service | Package distribution plus host policy |
| Remote service location | NCC discovery metadata, followed by independent trust and access checks |

A developer workflow could grow from the existing compiler, simulator, and Studio to include host capability declarations, NAP domain negotiation, event fixtures, permission review, adapter debugging, multi-host builds, and signed deployment. Make proposed capabilities and host support visible in the toolchain instead of implying portability from compilation alone.

## Recommended implementation roadmap

1. **Inventory and reconcile:** Inspect the current NScript napplet branch, NAP specifications/SDKs, and shell integrations. Record what is implemented in code, not only in proposals.
2. **Stabilize the narrow profile:** Document and test the existing lens profile, filter derivation, permission review, browser ABI, failure behavior, and version compatibility.
3. **Define typed NAP bindings:** Select one read-only domain and specify schemas, errors, capability mapping, version negotiation, and conformance vectors.
4. **Build a foreground reference host:** Implement the NCC Service Monitor using brokered read-only capabilities; verify no direct network, signer, or storage escape path.
5. **Add user-approved actions:** Introduce one narrow operation (such as a notification or intent) with explicit review and audit.
6. **Add portable browser execution:** Package the runtime and test the same program across an ordinary browser nsite and a compatible shell, documenting capability differences.
7. **Add a separate worker service:** Specify lifecycle, persistent state, revocation, quotas, restart behavior, and audits before implementing background execution.
8. **Integrate packages and Studio:** Clarify when an artifact is a napplet versus an npack package; surface build targets and host support.
9. **Explore remote or distributed execution:** Proceed only after authorization, trust, job lifecycle, idempotency, failure recovery, payments, and result-verification protocols are independently designed.

At each stage, add executable fixtures and tests according to the repository's contribution process. Do not treat a future milestone as complete until its implementation and conformance behavior are demonstrated.

## Risks and decisions to resolve

- **Capability boundary:** Which component enforces each permission: checker, runtime, adapter, shell, or remote service? Security-critical enforcement must be outside untrusted program logic.
- **Asynchronous semantics:** How are subscriptions, cancellation, backpressure, timeouts, and host errors represented in NScript?
- **Identity and signer model:** How do NIP-07, NIP-46, shell-mediated signing, and native signers map to one typed contract without exposing keys?
- **Trust and discovery:** Which NCC records and authorities are trusted, how are freshness and revocation handled, and who controls policy?
- **Isolation:** What process/WASM boundaries, quotas, and origin controls prevent a program or bundled JavaScript from reaching undeclared resources?
- **Durability:** What state is persisted, how are retries made idempotent, and how are program upgrades or revocations handled?
- **Portability:** Which behavior is guaranteed across browser, napplet, and native hosts, and which capabilities are optional?
- **Protocol maturity:** NAP domains, SDKs, shells, and proposed runtime features may have different implementation status; integrate behind adapters and track versions.
- **Distributed correctness:** Nostr events provide signed messages, not global consensus, confidentiality, guaranteed delivery, or exactly-once execution.

## References

Repository references:

- [NScript README](../README.md)
- [NCC tooling](NCC.md)
- [Napplet profile and embedding API](NAPPLETS.md)
- [npack](NPACK.md)
- [Compiler, runtime, and modules](COMPILER-RUNTIME-AND-MODULES.md)
- [NIP-5D manifest example](../examples/nip5d-manifest-audit.ns)
- [NCC service operator example](../examples/service-operator-bot.ns)
- [Napplet lens example](../examples/napplet-lens/README.md)
- [Napplet host adapter RFC](../rfcs/0003-napplets.md)

External specifications and projects referenced in the discussion (verify their current status before implementation):

- [NIP-5A: Nsites](https://github.com/nostr-protocol/nips/blob/master/5A.md)
- [NIP-5D: Napplet manifests](https://github.com/nostr-protocol/nips/pull/2303)
- [NAP specifications](https://github.com/napplet/naps)
- [Kehto web runtime toolkit](https://github.com/kehto/web)
- [Applesauce Nostr libraries](https://github.com/hzrd149/applesauce)

The integration ideas originated in the referenced “Nscript NCC Integration Ideas” conversation and are consolidated here as repository documentation. Implementation and syntax status should be rechecked against the repository before using examples as executable programs.
