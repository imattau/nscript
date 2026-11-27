import assert from "node:assert/strict";
import test from "node:test";
import { createNScriptNapplet } from "../src/index.js";

function mockRuntime({ available = true, checked = true, ready = true } = {}) {
  let onEvent;
  let closedSubscription = false;
  let closedSession = false;
  let receivedPrincipal;
  let receivedFilters;
  let receivedCeiling;
  const napplet = available
    ? {
        outbox: {
          subscribe(filters, _options) {
            receivedFilters = filters;
            return {
              on(_type, callback) { onEvent = callback; },
              close() { closedSubscription = true; },
            };
          },
          query() { return Promise.resolve({ events: [] }); },
        },
      }
    : {};
  const compiler = {
    nappletCheck(_source, ceiling, _modules, principal) {
      receivedCeiling = ceiling;
      receivedPrincipal = principal;
      return {
        ok: true,
        result: {
          checked,
          ready,
          requires: ["outbox"],
          principal_required: Boolean(principal === undefined),
          diagnostics: [],
          subscriptions: [{ kinds: [1], "#p": ["abcdef"], limit: 50 }],
          scope: { kind: "mentions" },
        },
      };
    },
    nappletOpen(_source, ceiling, _modules, principal) {
      receivedCeiling = ceiling;
      receivedPrincipal = principal;
      return {
        ok: true,
        result: {
          session: 7,
          checked,
          ready: principal === undefined ? false : ready,
          requires: ["outbox"],
          principal_required: principal === undefined,
          diagnostics: [],
          subscriptions: [{ kinds: [1], "#p": ["abcdef"], limit: 50 }],
          scope: { kind: "mentions" },
        },
      };
    },
    nappletEval(_session, event) {
      return {
        ok: true,
        result: {
          checked: true,
          matched: true,
          accepted: true,
          decisions: event.content === "spam"
            ? [{ action: "hide", reason: "promotion" }]
            : [{ action: "label", name: "topic", value: "nostr" }],
          logs: [],
          failures: [],
        },
      };
    },
    nappletClose() { closedSession = true; },
  };
  return {
    host: createNScriptNapplet({ napplet, compiler, capabilityCeiling: ["outbox", "identity"] }),
    emit(event) { onEvent({ event }); },
    isClosed() { return closedSubscription; },
    isSessionClosed() { return closedSession; },
    principal() { return receivedPrincipal; },
    filters() { return receivedFilters; },
    ceiling() { return receivedCeiling; },
  };
}

test("check forwards the enclosing applet capability ceiling and principal", () => {
  const mock = mockRuntime();
  const checked = mock.host.check("source", { principal: "abcdef" });
  assert.equal(checked.checked, true);
  assert.deepEqual(mock.ceiling(), ["outbox", "identity"]);
  assert.equal(mock.principal(), "abcdef");
});

test("check rejects when the required domain exceeds the ceiling", () => {
  const compiler = {
    nappletCheck: () => ({ ok: true, result: { checked: true, requires: ["outbox"] } }),
  };
  const host = createNScriptNapplet({ napplet: {}, compiler, capabilityCeiling: [] });
  assert.throws(() => host.check("source"), /capability ceiling/);
});

test("start uses the derived mentions filter and reports decisions", async () => {
  const mock = mockRuntime();
  const decisions = [];
  const subscription = await mock.host.start("source", {
    principal: "abcdef",
    onDecision(payload) { decisions.push(payload); },
  });
  mock.emit({ id: "event-1", kind: 1, content: "spam", tags: [["p", "abcdef"]] });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(decisions.length, 1);
  assert.deepEqual(decisions[0].decisions, [{ action: "hide", reason: "promotion" }]);
  assert.deepEqual(mock.filters(), [{ kinds: [1], "#p": ["abcdef"], limit: 50 }]);
  assert.equal(mock.principal(), "abcdef");
  subscription.stop();
  assert.equal(mock.isClosed(), true);
  assert.equal(mock.isSessionClosed(), true);
});

test("start fails clearly when the shell omits a required domain", async () => {
  const mock = mockRuntime({ available: false });
  await assert.rejects(
    () => mock.host.start("source", { principal: "abcdef", onDecision() {} }),
    /does not provide/,
  );
});

test("start refuses a script that needs a principal when none is connected", async () => {
  const mock = mockRuntime({ ready: false });
  await assert.rejects(
    () => mock.host.start("source", { onDecision() {} }),
    /Connect a signer/,
  );
  assert.equal(mock.isSessionClosed(), true);
});
