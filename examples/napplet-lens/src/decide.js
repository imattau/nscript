const MAX_LABELS = 8;
const MAX_DECISIONS = 32;

/**
 * Reduces a checked program's decision list to the presentation state for one
 * event. Hide is terminal; labels accumulate; pin and flag keep the first
 * reason. A malformed decision is ignored rather than hiding content.
 *
 * @param {Array<{action: string, reason?: string, name?: string, value?: string}>} decisions
 * @returns {{hidden: string|null, pinned: string|null, flagged: string|null, labels: Array<{name: string, value: string}>}}
 */
export function reduceDecisions(decisions) {
  const labels = [];
  let hidden = null;
  let pinned = null;
  let flagged = null;
  for (const decision of Array.isArray(decisions) ? decisions.slice(0, MAX_DECISIONS) : []) {
    if (!decision || typeof decision.action !== "string") continue;
    if (decision.action === "hide") {
      hidden ??= text(decision.reason) ?? "hidden by rule";
    } else if (decision.action === "pin") {
      pinned ??= text(decision.reason) ?? "pinned by rule";
    } else if (decision.action === "flag") {
      flagged ??= text(decision.reason) ?? "flagged by rule";
    } else if (decision.action === "label") {
      const name = text(decision.name);
      const value = text(decision.value);
      if (!name || !value) continue;
      if (labels.length >= MAX_LABELS) continue;
      if (!labels.some((label) => label.name === name && label.value === value)) {
        labels.push({ name, value });
      }
    }
  }
  return { hidden, pinned, flagged, labels };
}

/**
 * Builds the render item for an event and its decisions.
 *
 * @param {object} event
 * @param {object[]} decisions
 * @param {object[]} failures
 * @returns {object}
 */
export function presentEvent(event, decisions, failures = []) {
  const presentation = reduceDecisions(decisions);
  return {
    id: String(event.id),
    event,
    hidden: presentation.hidden,
    pinned: presentation.pinned,
    flagged: presentation.flagged,
    labels: presentation.labels,
    failures: Array.isArray(failures) ? failures : [],
  };
}

/**
 * Sorts pinned notes first, then newest first.
 *
 * @param {object[]} items
 * @returns {object[]}
 */
export function sortItems(items) {
  return [...items].sort((left, right) => {
    if (Boolean(left.pinned) !== Boolean(right.pinned)) return left.pinned ? -1 : 1;
    return (right.event.created_at ?? 0) - (left.event.created_at ?? 0);
  });
}

function text(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, 200);
}
