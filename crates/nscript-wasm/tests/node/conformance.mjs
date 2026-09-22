// NScript compiler conformance through the wasm ABI.
//
// Walks the conformance corpus and drives the wasm artifact the same way a
// browser Studio will: `valid/*.ns` must analyze clean, `invalid/*.ns` must
// report the diagnostic code named in their leading `// error:` comment.
//
// Run: scripts/wasm-conformance.sh (or after building the wasm target):
//   node crates/nscript-wasm/tests/node/conformance.mjs

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../../..");
const wasmPath = join(
  root,
  "target/wasm32-unknown-unknown/release/nscript_wasm.wasm",
);

const { instance } = await WebAssembly.instantiate(
  readFileSync(wasmPath),
  {},
);
const {
  memory,
  nscript_abi,
  nscript_alloc,
  nscript_dealloc,
  nscript_handle,
  nscript_free,
} = instance.exports;

const abi = nscript_abi();
if (abi !== 1) {
  throw new Error(`unexpected wasm ABI version ${abi}`);
}

function call(request) {
  const bytes = new TextEncoder().encode(JSON.stringify(request));
  const ptr = nscript_alloc(bytes.length);
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  const outPtr = nscript_handle(ptr, bytes.length);
  nscript_dealloc(ptr, bytes.length);
  const view = new Uint8Array(memory.buffer);
  let length = 0;
  while (view[outPtr + length] !== 0) {
    length += 1;
  }
  const text = new TextDecoder().decode(view.slice(outPtr, outPtr + length));
  nscript_free(outPtr, length + 1);
  return JSON.parse(text);
}

const invalid = join(root, "conformance/invalid");
const valid = join(root, "conformance/valid");

function expectedCodes(source) {
  return [...source.matchAll(/^\/\/ error:\s*([A-Z][0-9]+)/gm)].map(
    (match) => match[1],
  );
}

let failures = 0;

for (const file of readdirSync(valid).filter((name) => name.endsWith(".ns")).sort()) {
  const source = readFileSync(join(valid, file), "utf8");
  const response = call({ op: "inspect", source });
  if (!response.ok) {
    failures += 1;
    console.error(`FAIL valid/${file}: request error ${response.error.message}`);
    continue;
  }
  const diagnostics = response.result.diagnostics;
  if (diagnostics.length !== 0) {
    failures += 1;
    console.error(
      `FAIL valid/${file}: expected no diagnostics, got ${diagnostics
        .map((d) => d.code)
        .join(", ")}`,
    );
  }
}

for (const file of readdirSync(invalid).filter((name) => name.endsWith(".ns")).sort()) {
  const source = readFileSync(join(invalid, file), "utf8");
  const response = call({ op: "inspect", source });
  if (!response.ok) {
    failures += 1;
    console.error(`FAIL invalid/${file}: request error ${response.error.message}`);
    continue;
  }
  const codes = new Set(response.result.diagnostics.map((d) => d.code));
  for (const code of expectedCodes(source)) {
    if (!codes.has(code)) {
      failures += 1;
      console.error(
        `FAIL invalid/${file}: expected ${code}, got ${[...codes].join(", ")}`,
      );
    }
  }
}

if (failures === 0) {
  console.log(`conformance OK through wasm ABI`);
} else {
  console.error(`${failures} conformance failure(s)`);
  process.exit(1);
}

// Editor-analysis smoke: the same ops the Studio editor will call.
function assert(condition, message) {
  if (!condition) {
    console.error(`FAIL ${message}`);
    process.exit(1);
  }
}

const source = "use nip01\non Note {\n    event.\n}\n";
const completions = call({
  op: "completions",
  source,
  offset: source.indexOf("event.") + "event.".length,
});
assert(completions.ok, "completions request failed");
const labels = completions.result.completions.map((c) => c.label);
assert(labels.includes("content"), `event members include content, got ${labels}`);

const useSource = "use nip\n";
const useCompletions = call({
  op: "completions",
  source: useSource,
  offset: useSource.length - 1,
});
assert(
  useCompletions.result.completions.some((c) => c.label === "nip17"),
  "`use nip` offers nip17",
);

const hoverSource = "use nip17\n";
const hover = call({
  op: "hover",
  source: hoverSource,
  offset: hoverSource.indexOf("nip17") + 2,
});
assert(hover.result.hover && hover.result.hover.label === "nip17", "hover names the module");

const symbols = call({ op: "symbols", source });
assert(symbols.result.symbols.length > 0, "symbols are listed");

const testEvent = call({
  op: "test_event",
  source:
    "use nip01\npermissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    print(event.content)\n}\n",
  event: { kind: 1, content: "hello" },
});
assert(testEvent.result.executed, "test_event executed");
assert(testEvent.result.report.dispatched === 1, "test_event dispatched the handler");
assert(testEvent.result.report.logs[0].message === "hello", "test_event ran the body");

console.log("editor-analysis ops OK through wasm ABI");