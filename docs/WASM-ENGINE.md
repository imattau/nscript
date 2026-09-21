# WASM engine decision

NScript will target **Wasmi** as the primary embedded WASM engine.

Why Wasmi fits the runtime:

- lightweight interpreter suitable for constrained hosts;
- deterministic execution model;
- built-in fuel metering for instruction budgets;
- no implicit WASI, filesystem, networking, or process authority;
- smaller dependency and build footprint than a JIT-oriented engine;
- straightforward mapping to the existing capability/import boundary.

Wasmtime remains an optional backend for deployments that need JIT/AOT
performance. Its resource limiter and fuel APIs are strong, but its larger
runtime footprint and broader feature surface are not appropriate as the
Draft 0.1 default. Any Wasmtime integration must configure memory/table
limits, fuel, and host-call data limits explicitly.

## Integration order

1. Add Wasmi behind a `wasm-engine` Cargo feature.
2. Instantiate modules with no WASI imports.
3. Bind only `nscript` capability and operation imports.
4. Set fuel and memory limits before calling `nscript_main`.
5. Route imports through `WasmDispatchHost` and existing relay/signer/storage
adapters.
6. Keep the reference executor available for deterministic offline tests.

Every Wasmi execution receives a finite fuel budget; exhaustion is surfaced as
a runtime failure before untrusted execution can continue past its allowance.
The store also caps linear memory at 16 MiB and limits instance/table creation,
so artifacts cannot grow host-managed WASM resources without bound.
Embedding hosts may tighten these values with `WasmiEngine::with_limits`; the
default constructor keeps the 16 MiB/one-instance/one-table policy.
Payload imports are also checked for canonical operation names and unique
indices before a module is instantiated.
