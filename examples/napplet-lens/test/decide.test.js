import assert from "node:assert/strict";
import test from "node:test";
import { presentEvent, reduceDecisions, sortItems } from "../src/decide.js";

test("hide is terminal and keeps its reason", () => {
  const result = reduceDecisions([
    { action: "label", name: "topic", value: "nostr" },
    { action: "hide", reason: "promotion" },
    { action: "pin", reason: "priority" },
  ]);
  assert.equal(result.hidden, "promotion");
  assert.equal(result.pinned, "priority");
  assert.deepEqual(result.labels, [{ name: "topic", value: "nostr" }]);
});

test("labels deduplicate and malformed decisions are ignored", () => {
  const result = reduceDecisions([
    { action: "label", name: "topic", value: "nostr" },
    { action: "label", name: "topic", value: "nostr" },
    { action: "label", name: "topic" },
    { action: "wat" },
    null,
  ]);
  assert.deepEqual(result.labels, [{ name: "topic", value: "nostr" }]);
  assert.equal(result.hidden, null);
});

test("presentEvent keeps failures but never hides because of them", () => {
  const item = presentEvent(
    { id: "one", content: "hello", created_at: 10 },
    [],
    [{ handler: "Note", error: "boom" }],
  );
  assert.equal(item.hidden, null);
  assert.equal(item.failures.length, 1);
});

test("pinned notes sort first, then by created_at", () => {
  const items = [
    { pinned: null, event: { created_at: 30 } },
    { pinned: "priority", event: { created_at: 10 } },
    { pinned: null, event: { created_at: 20 } },
  ];
  assert.deepEqual(
    sortItems(items).map((item) => item.event.created_at),
    [10, 30, 20],
  );
});
