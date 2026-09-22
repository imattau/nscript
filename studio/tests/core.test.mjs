// Exercises the Studio's wasm glue and panel logic in node, against the real
// wasm artifact built by `scripts/wasm-conformance.sh`.
//
// Run: npm test (after `npm run wasm` / the wasm build).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

import { createClient } from "../src/wasm.mjs";
import {
  diagnosticsToMarkers,
  fixtures,
  mapFootprint,
  templates,
  describeReport,
  buildChecklist,
  decodeBase64,
  describeIr,
} from "../src/core.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const wasmPath = join(
  root,
  "target/wasm32-unknown-unknown/release/nscript_wasm.wasm",
);

const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const client = createClient(instance);

test("wasm glue loads and answers basic ops", () => {
  assert.equal(client.abi, 1);
  const response = client.analyze("use nip01\n");
  assert.ok(response.ok);
  assert.deepEqual(response.result.diagnostics, []);
});

test("templates all analyze clean", () => {
  for (const template of templates()) {
    if (!template.source) continue;
    const response = client.inspect(template.source);
    assert.ok(response.ok, `${template.name} request failed`);
    assert.deepEqual(
      response.result.diagnostics,
      [],
      `${template.name} should be clean`,
    );
  }
});

test("footprint maps zap to a requested payment live", () => {
  const source = "use nip57\nzap alice amount 1000\n";
  const response = client.footprint(source);
  assert.ok(response.ok);
  const { groups, requested } = mapFootprint(response.result.footprint);
  const payments = groups.find((group) => group.name === "Payments");
  assert.ok(payments, "Payments group exists");
  assert.ok(
    payments.items.some((item) => item.status === "requested"),
    "zap shows as requested",
  );
  assert.ok(requested.length >= 1);
});

test("diagnostics map to monaco markers", () => {
  const response = client.inspect("publish Note { content: \"hi\" }\n");
  assert.ok(response.result.diagnostics.length >= 1);
  const markers = diagnosticsToMarkers(response.result.diagnostics);
  assert.ok(markers.length >= 1);
  assert.ok(markers[0].startLineNumber >= 1);
  assert.ok(markers[0].message.startsWith("E"));
});

test("completions and hover work through the glue", () => {
  const source = "use nip01\non Note {\n    event.\n}\n";
  const offset = source.indexOf("event.") + "event.".length;
  const completions = client.completions(source, offset);
  const labels = completions.result.completions.map((c) => c.label);
  assert.ok(labels.includes("content"), `has content, got ${labels}`);

  const hover = client.hover("use nip17\n", "use nip17\n".indexOf("nip17") + 2);
  assert.equal(hover.result.hover.label, "nip17");
});

test("test event runs a template handler and formats a report", () => {
  const template = templates().find((item) => item.name === "Keyword monitor");
  const event = fixtures().find((item) => item.name === "Note").event;
  const response = client.testEvent(template.source, { ...event, content: "nostrhost here" });
  assert.ok(response.ok, "request succeeded");
  assert.equal(response.result.executed, true);
  assert.equal(response.result.report.dispatched, 1);
  const text = describeReport(response.result.report);
  assert.ok(text.includes("Matched: 1/1 handlers"));
  assert.ok(text.includes("log info: found:"));
});

test("build produces a manifest, lockfile, and downloadable wasm", () => {
  const template = templates().find((item) => item.name === "Auto-reply bot");
  const manifest = client.manifest(
    template.source,
    "npub1author",
    "auto-responder",
    "1.2.0",
  );
  assert.ok(manifest.ok, "manifest request succeeded");
  assert.equal(manifest.result.checked, true);
  const checklist = buildChecklist(manifest.result);
  assert.ok(checklist.every((step) => step.ok), checklist.map((s) => `${s.step}:${s.ok}`).join(" "));
  assert.equal(manifest.result.manifest.name, "auto-responder");
  assert.equal(manifest.result.manifest.version, "1.2.0");
  assert.equal(manifest.result.manifest.format, "npk");
  assert.equal(manifest.result.manifest.sha256.length, 64);
  const bytes = decodeBase64(manifest.result.wasm);
  assert.equal(bytes.length, manifest.result.bytes);
  assert.deepEqual([...bytes.subarray(0, 4)], [0x00, 0x61, 0x73, 0x6d], "wasm magic");

  const lock = client.lock(template.source);
  assert.ok(lock.result.lockfile);
  assert.equal(lock.result.lockfile.lockfile_version, 1);
  assert.ok(
    lock.result.lockfile.modules.some((module) => module.name === "nip17"),
    "nip17 in the lockfile",
  );
});

test("the lowering inspector renders the create/sign/publish chain", () => {
  const source = "use nip01\nsigner account = nip46()\nrelayset public = configured\n\ndefaults {\n    signer: account\n    relays: public\n}\n\npermissions {\n    publish Note to public\n    sign Note with account\n    relay public\n}\n\npublish Note { content: \"hi\" }\n";
  const ir = client.ir(source);
  assert.ok(ir.ok && ir.result.checked, "ir lowers");
  const text = describeIr(ir.result.ir);
  assert.ok(text.includes("create_event"), text);
  assert.ok(text.includes("sign_event"), text);
  assert.ok(text.includes("publish_event"), text);
  assert.ok(text.includes("permission relay"), text);
});