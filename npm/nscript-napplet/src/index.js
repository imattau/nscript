const DEFAULT_FILTERS = [{ kinds: [1], limit: 50 }];
const MAX_EVENT_BYTES = 256_000;
const MAX_PENDING_EVENTS = 100;
const EVENT_INTERVAL_MS = 40;

/**
 * Creates an embeddable checked NScript "lens" runtime for a napplet.
 *
 * The caller supplies the compiler WASM client, the shell's injected NAP
 * namespace, and the enclosing applet's maximum domain set. User scripts
 * never receive the namespace. The adapter implements the read-only Note
 * lens profile, which requires `outbox` and may use `identity` and `storage`
 * in the enclosing applet.
 *
 * @param {{napplet: object, compiler: object, capabilityCeiling?: string[], filters?: object[], limit?: number}} options
 * @returns {{
 *   available: boolean,
 *   check(source: string, options?: {principal?: string, limit?: number}): object,
 *   start(source: string, handlers: object): Promise<{stop(): void}>
 * }}
 */
export function createNScriptNapplet({
  napplet,
  compiler,
  capabilityCeiling = ["outbox"],
  filters = DEFAULT_FILTERS,
  limit = 50,
}) {
  if (!compiler || typeof compiler.nappletCheck !== "function") {
    throw new TypeError("compiler must provide nappletCheck");
  }
  if (!Array.isArray(capabilityCeiling) || capabilityCeiling.some((domain) => typeof domain !== "string")) {
    throw new TypeError("capabilityCeiling must be an array of NAP domain names");
  }
  const ceiling = [...new Set(capabilityCeiling)];

  function check(source, { principal, limit: requestedLimit } = {}) {
    const response = compiler.nappletCheck(source, ceiling, [], principal, requestedLimit ?? limit);
    if (!response.ok) throw new Error(response.error?.message ?? "NScript check failed.");
    const result = response.result;
    if (result.checked && result.requires?.some((domain) => !ceiling.includes(domain))) {
      throw new Error("NScript requirement exceeds the enclosing applet capability ceiling.");
    }
    return result;
  }

  function requireShellDomains(requirements) {
    for (const domain of requirements ?? []) {
      if (!napplet?.[domain]) {
        throw new Error(`The shell does not provide required NAP domain '${domain}'.`);
      }
    }
  }

  function open(source, { principal, limit: requestedLimit } = {}) {
    if (typeof compiler.nappletOpen === "function") {
      const response = compiler.nappletOpen(
        source,
        ceiling,
        [],
        principal,
        requestedLimit ?? limit,
      );
      if (!response.ok) throw new Error(response.error?.message ?? "NScript open failed.");
      const result = response.result;
      if (result.checked && result.requires?.some((domain) => !ceiling.includes(domain))) {
        close(result.session ?? null);
        throw new Error("NScript requirement exceeds the enclosing applet capability ceiling.");
      }
      return { result, session: result?.session ?? null };
    }
    const result = check(source, { principal, limit: requestedLimit });
    return { result, session: null };
  }

  function evaluate(session, source, event, principal) {
    if (session == null) {
      const response = compiler.nappletEvent(source, event, ceiling, [], principal);
      if (!response.ok) throw new Error(response.error?.message ?? "NScript event evaluation failed.");
      return response.result;
    }
    const response = compiler.nappletEval(session, event);
    if (!response.ok) throw new Error(response.error?.message ?? "NScript event evaluation failed.");
    return response.result;
  }

  function close(session) {
    if (session == null || typeof compiler.nappletClose !== "function") return;
    try {
      compiler.nappletClose(session);
    } catch {
      // A torn-down wasm session is not a user-facing failure.
    }
  }

  async function start(
    source,
    {
      principal,
      limit: requestedLimit,
      onDecision,
      onAccepted,
      onLog = () => {},
      onError = () => {},
    } = {},
  ) {
    if (typeof onDecision !== "function" && typeof onAccepted !== "function") {
      throw new TypeError("start requires an onDecision or onAccepted callback");
    }
    const { result, session } = open(source, { principal, limit: requestedLimit });
    if (!result.checked) {
      close(session);
      throw new Error(result.diagnostics?.[0]?.message ?? "Fix NScript diagnostics before activation.");
    }
    if (result.ready === false) {
      close(session);
      throw new Error(
        result.principal_required
          ? "This script uses `me`. Connect a signer before activating it."
          : "The script is not ready to run.",
      );
    }
    try {
      requireShellDomains(result.requires);
    } catch (error) {
      close(session);
      throw error;
    }
    const outbox = napplet.outbox;
    const derived = Array.isArray(result.subscriptions) && result.subscriptions.length
      ? result.subscriptions
      : filters;

    let active = true;
    let draining = false;
    const seen = new Set();
    const pending = [];
    const reportError = (error) => {
      if (active) onError(error instanceof Error ? error : new Error(String(error)));
    };
    const dispatch = (event) => {
      if (!active) return;
      const eventResult = evaluate(session, source, event, principal);
      if (!eventResult.checked || eventResult.diagnostics?.length) {
        throw new Error(eventResult.diagnostics?.[0]?.message ?? "NScript event program was rejected.");
      }
      const payload = {
        event,
        decisions: eventResult.decisions ?? [],
        logs: eventResult.logs ?? [],
        failures: eventResult.failures ?? [],
        matched: eventResult.matched ?? eventResult.accepted ?? true,
        accepted: eventResult.accepted ?? false,
      };
      if (typeof onDecision === "function") onDecision(payload);
      else onAccepted(event, payload.logs);
      for (const record of payload.logs) onLog(record, event);
    };
    const queue = (event) => {
      if (!active || !event || typeof event.id !== "string" || seen.has(event.id)) return;
      let size;
      try {
        size = new TextEncoder().encode(JSON.stringify(event)).length;
      } catch {
        return;
      }
      if (size > MAX_EVENT_BYTES) return;
      seen.add(event.id);
      if (seen.size > 500) seen.delete(seen.values().next().value);
      pending.push(event);
      if (pending.length > MAX_PENDING_EVENTS) pending.shift();
      if (draining) return;
      draining = true;
      void (async () => {
        while (active && pending.length) {
          const next = pending.shift();
          try {
            dispatch(next);
          } catch (error) {
            reportError(error);
          }
          if (pending.length) await new Promise((resolve) => setTimeout(resolve, EVENT_INTERVAL_MS));
        }
        draining = false;
      })();
    };

    let subscription;
    try {
      subscription = outbox.subscribe(derived, { timeoutMs: 5_000, limit: requestedLimit ?? limit });
      subscription.on("event", (delivery) => queue(delivery?.event ?? delivery));
      outbox
        .query(derived, { timeoutMs: 5_000, limit: requestedLimit ?? limit })
        .then((response) => (response?.events ?? []).forEach((delivery) => queue(delivery?.event ?? delivery)))
        .catch(reportError);
    } catch (error) {
      close(session);
      throw error;
    }

    return {
      result,
      stop() {
        if (!active) return;
        active = false;
        pending.length = 0;
        try {
          subscription?.close();
        } catch {
          // The shell can revoke a subscription during navigation.
        }
        close(session);
      },
    };
  }

  return Object.freeze({
    get available() {
      return Boolean(napplet?.outbox);
    },
    check,
    start,
  });
}
