import { loadWasmBytes } from "../../../studio/src/wasm.mjs";
import { createNScriptNapplet } from "@nscript/napplet";
import compilerBytes from "./compiler-wasm.js";
import { presentEvent, sortItems } from "./decide.js";
import "./style.css";
import mentionsPreset from "../presets/mentions.ns?raw";
import followingPreset from "../presets/following.ns?raw";
import personalPreset from "../presets/personal.ns?raw";
import topicPreset from "../presets/topic.ns?raw";
import blankPreset from "../presets/blank.ns?raw";

const PRESETS = {
  mentions: mentionsPreset,
  following: followingPreset,
  personal: personalPreset,
  topic: topicPreset,
  blank: blankPreset,
};
const DEFAULT_PRESET = "mentions";
const SOURCE_KEY = "nscript-lens-source-v2";
const MAX_SOURCE_LENGTH = 32_000;
const MAX_ITEMS = 200;

const sourceEditor = document.querySelector("#source");
const status = document.querySelector("#status");
const statusDot = document.querySelector("#status-dot");
const identityName = document.querySelector("#identity-name");
const identityKey = document.querySelector("#identity-key");
const compileState = document.querySelector("#compile-state");
const footprint = document.querySelector("#footprint");
const diagnostics = document.querySelector("#diagnostics");
const reviewSummary = document.querySelector("#review-summary");
const scopeChip = document.querySelector("#scope-chip");
const scopeNote = document.querySelector("#scope-note");
const domains = document.querySelector("#domains");
const domainsNote = document.querySelector("#domains-note");
const storageNote = document.querySelector("#storage-note");
const activateButton = document.querySelector("#activate");
const stopButton = document.querySelector("#stop");
const presetSelect = document.querySelector("#preset");
const feed = document.querySelector("#feed");
const count = document.querySelector("#count");
const feedHint = document.querySelector("#feed-hint");
const statScanned = document.querySelector("#stat-scanned");
const statKept = document.querySelector("#stat-kept");
const statHidden = document.querySelector("#stat-hidden");
const statLabeled = document.querySelector("#stat-labeled");
const statErrors = document.querySelector("#stat-errors");
const tabs = [...document.querySelectorAll(".tab")];

let compiler;
let lensHost;
let activeFeed;
let activeSource;
let principal;
let identitySubscription;
let checkTimer;
let saveTimer;
let running = false;
let review = null;
let currentFilter = "all";
let items = new Map();
let order = [];

function setStatus(message, mode = "idle") {
  status.textContent = message;
  statusDot.dataset.mode = mode;
}

function shortKey(value) {
  if (!value) return "";
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function setIdentity(name, key, note) {
  identityName.textContent = name;
  identityKey.textContent = key;
  identityKey.title = note ?? key;
}

function storageHandle() {
  return window.napplet?.storage?.instance ?? window.napplet?.storage;
}

function renderDiagnostics(list, fallback = null) {
  diagnostics.replaceChildren();
  const entries = list?.length ? list : fallback ? [fallback] : [];
  diagnostics.hidden = entries.length === 0;
  if (!entries.length) return;
  const heading = document.createElement("p");
  heading.className = "diagnostics-heading";
  heading.textContent = "Fix these before activation";
  const ul = document.createElement("ul");
  for (const entry of entries.slice(0, 8)) {
    const li = document.createElement("li");
    const where = entry.line ? `line ${entry.line}: ` : "";
    li.textContent = `${entry.code ?? "NScript"} · ${where}${entry.message ?? entry}`;
    ul.append(li);
  }
  diagnostics.append(heading, ul);
}

function friendlyCapability(label) {
  const map = {
    "Call lens.hide": "Hide notes in this view",
    "Call lens.label": "Label notes in this view",
    "Call lens.pin": "Pin notes in this view",
    "Call lens.flag": "Flag notes in this view",
  };
  return map[label] ?? label;
}

function renderReview(result) {
  footprint.replaceChildren();
  reviewSummary.replaceChildren();
  const checked = result?.checked;
  const ready = result?.ready;
  if (!checked) {
    reviewSummary.textContent = "The rule is not checked yet.";
    renderDiagnostics(result?.diagnostics ?? [], null);
    setScope("Fix the rule first", "Nothing is fetched until the program checks.");
    activateButton.disabled = true;
    compileState.textContent = "Activation blocked";
    return;
  }

  const needsPrincipal = Boolean(result.principal_required) && !principal;
  const summary = document.createElement("p");
  summary.textContent = !lensHost?.available
    ? "This rule is checked locally, but the shell does not provide the required outbox domain."
    : needsPrincipal
      ? "This rule reads your mentions. Connect a signer to activate it."
      : `Reads ${String(result.scope?.label ?? "notes").toLowerCase()} and makes local view decisions. Nothing is published or signed.`;
  reviewSummary.append(summary);

  const groups = result.footprint?.groups ?? [];
  const list = document.createElement("ul");
  list.className = "capability-list";
  for (const group of groups) {
    for (const item of group.items ?? []) {
      const row = document.createElement("li");
      const mark = document.createElement("span");
      mark.className = item.status === "granted" ? "check" : "requested";
      mark.textContent = item.status === "granted" ? "•" : "!";
      const label = document.createElement("span");
      label.textContent = friendlyCapability(item.label);
      row.append(mark, label);
      list.append(row);
    }
  }
  if (!list.children.length) {
    const row = document.createElement("li");
    row.textContent = "No capability details.";
    list.append(row);
  }
  footprint.append(list);

  renderDiagnostics(result.diagnostics ?? [], null);
  setScope(result.scope?.label ?? "Notes", describeFilters(result.subscriptions));
  const required = result.requires ?? [];
  const optional = result.optional ?? [];
  domains.textContent = required.join(", ") || "outbox";
  domainsNote.textContent = optional.length
    ? `Optional: ${optional.join(", ")}. The shell remains authoritative.`
    : "Relay reads stay behind the shell.";
  compileState.textContent = !lensHost?.available
    ? "outbox unavailable · activation disabled"
    : needsPrincipal
      ? "Connect a signer to run mentions rules"
      : ready
        ? "Checked · ready"
        : "Waiting for a signer";
  activateButton.disabled = !ready || !lensHost?.available;
}

function setScope(label, detail) {
  scopeChip.textContent = `Reading: ${label}`;
  scopeNote.textContent = detail;
}

function describeFilters(filters) {
  if (!Array.isArray(filters) || !filters.length) return "No outbox query yet.";
  if (filters.length > 1) return `${filters.length} outbox query scopes.`;
  const filter = filters[0] ?? {};
  if (Array.isArray(filter["#p"])) return "Handler predicate → #p mention filter.";
  if (Array.isArray(filter["#t"])) return `Handler predicate → #t ${filter["#t"].join(", ")} filter.`;
  if (Array.isArray(filter.authors) && filter.authors.length) {
    return `Handler predicate → ${filter.authors.length} author filter.`;
  }
  return "No narrowing predicate → the shell's outbox feed.";
}

async function checkSource() {
  if (!lensHost) return null;
  const source = sourceEditor.value;
  if (source.length > MAX_SOURCE_LENGTH) {
    review = {
      checked: false,
      diagnostics: [{ code: "NAPPLET003", message: `Source is limited to ${MAX_SOURCE_LENGTH} characters.` }],
    };
    renderReview(review);
    return review;
  }
  let result;
  try {
    result = lensHost.check(source, { principal });
  } catch (error) {
    review = {
      checked: false,
      diagnostics: [{ code: "NAPPLET004", message: error.message }],
    };
    renderReview(review);
    return review;
  }
  review = result;
  renderReview(result);
  if (running && source !== activeSource) {
    stopSubscription("Rule changed. Activate it again to use the new version.");
    renderReview(result);
  }
  return result;
}

async function activate() {
  if (!lensHost?.available) {
    setStatus("The shell does not provide outbox.", "error");
    return;
  }
  const result = await checkSource();
  if (!result?.checked || !result.ready) return;
  stopSubscription("Replacing the active lens…");
  clearFeed();
  activeSource = sourceEditor.value;
  try {
    activeFeed = await lensHost.start(activeSource, {
      principal,
      onDecision: handleDecision,
      onError: (error) => {
        feedHint.textContent = error.message;
        setStatus("A rule event failed", "error");
      },
    });
    running = true;
    activateButton.disabled = true;
    stopButton.disabled = false;
    feedHint.textContent = "Listening through the shell. Matching notes appear below.";
    setStatus("Lens active", "active");
  } catch (error) {
    stopSubscription("Could not start the lens.");
    setStatus(error?.message ?? "The shell rejected the request.", "error");
  }
}

function stopSubscription(message = "Lens stopped.") {
  activeFeed?.stop();
  activeFeed = undefined;
  activeSource = undefined;
  running = false;
  activateButton.disabled = !lensHost?.available || !review?.checked || !review?.ready;
  stopButton.disabled = true;
  feedHint.textContent = "Activate a checked rule to start the lens.";
  setStatus(message, "idle");
}

function handleDecision(payload) {
  if (!payload?.event?.id) return;
  if (payload.matched === false) return;
  const item = presentEvent(payload.event, payload.decisions ?? [], payload.failures ?? []);
  if (!items.has(item.id)) order.unshift(item.id);
  items.set(item.id, item);
  while (order.length > MAX_ITEMS) {
    const dropped = order.pop();
    items.delete(dropped);
  }
  renderFeed();
}

function clearFeed() {
  items = new Map();
  order = [];
  renderFeed();
}

function visibleItems() {
  const sorted = sortItems(order.map((id) => items.get(id)).filter(Boolean));
  if (currentFilter === "hidden") return sorted.filter((item) => item.hidden);
  if (currentFilter === "labeled") return sorted.filter((item) => item.labels.length > 0 && !item.hidden);
  return sorted.filter((item) => !item.hidden);
}

function renderFeed() {
  const all = [...items.values()];
  const hidden = all.filter((item) => item.hidden).length;
  const labeled = all.filter((item) => item.labels.length > 0).length;
  const errors = all.filter((item) => item.failures.length > 0).length;
  count.textContent = String(visibleItems().length);
  statScanned.textContent = String(all.length);
  statKept.textContent = String(all.length - hidden);
  statHidden.textContent = String(hidden);
  statLabeled.textContent = String(labeled);
  statErrors.textContent = String(errors);

  const list = visibleItems();
  feed.replaceChildren();
  if (!list.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = currentFilter === "hidden"
      ? "No hidden notes yet."
      : currentFilter === "labeled"
        ? "No labeled notes yet."
        : running
          ? "Listening for notes that match the rule…"
          : "Nothing here yet. Activate a checked rule to start the lens.";
    feed.append(empty);
    return;
  }
  for (const item of list) feed.append(renderCard(item));
}

function renderCard(item) {
  const card = document.createElement("article");
  card.className = `note-card${item.hidden ? " is-hidden" : ""}${item.pinned ? " is-pinned" : ""}`;

  const meta = document.createElement("div");
  meta.className = "note-meta";
  const author = document.createElement("span");
  author.className = "author";
  author.textContent = shortKey(item.event.pubkey ?? item.event.signer ?? "unknown author");
  const date = document.createElement("time");
  date.textContent = item.event.created_at
    ? new Date(item.event.created_at * 1000).toLocaleString()
    : "Nostr note";
  meta.append(author, date);

  const badges = document.createElement("div");
  badges.className = "badges";
  if (item.pinned) badges.append(badge(`pinned · ${item.pinned}`, "pin"));
  if (item.hidden) badges.append(badge(`hidden · ${item.hidden}`, "hide"));
  if (item.flagged) badges.append(badge(`flag · ${item.flagged}`, "flag"));
  for (const label of item.labels) badges.append(badge(`${label.name}: ${label.value}`, "label"));
  if (item.failures.length) badges.append(badge("rule error", "error"));
  if (badges.children.length) meta.append(badges);

  const body = document.createElement("p");
  body.className = "note-body";
  body.textContent = item.event.content ?? "";

  card.append(meta, body);
  if (item.failures.length) {
    const error = document.createElement("p");
    error.className = "rule-error";
    error.textContent = item.failures.map((failure) => `${failure.handler}: ${failure.error}`).join(" · ");
    card.append(error);
  }
  return card;
}

function badge(text, kind) {
  const span = document.createElement("span");
  span.className = `badge badge-${kind}`;
  span.textContent = text;
  return span;
}

function selectFilter(filter) {
  currentFilter = filter;
  for (const tab of tabs) {
    const active = tab.dataset.filter === filter;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  }
  renderFeed();
}

async function loadPreset(name, { persist = true } = {}) {
  const source = PRESETS[name] ?? PRESETS[DEFAULT_PRESET];
  sourceEditor.value = source;
  presetSelect.value = name;
  if (persist) persistSource();
  await checkSource();
}

async function restoreSource() {
  const store = storageHandle();
  if (!store?.getItem || !store?.setItem) {
    storageNote.textContent = "Storage is unavailable; edits last for this session.";
    await loadPreset(DEFAULT_PRESET, { persist: false });
    return;
  }
  try {
    const saved = await store.getItem(SOURCE_KEY);
    sourceEditor.value = saved || PRESETS[DEFAULT_PRESET];
    storageNote.textContent = "Rules are saved through shell storage.";
  } catch {
    sourceEditor.value = PRESETS[DEFAULT_PRESET];
    storageNote.textContent = "Shell storage could not be read; edits last for this session.";
  }
  presetSelect.value = detectPreset(sourceEditor.value);
  await checkSource();
}

function detectPreset(source) {
  return Object.entries(PRESETS).find(([, value]) => value === source)?.[0] ?? DEFAULT_PRESET;
}

function persistSource() {
  const store = storageHandle();
  if (!store?.setItem) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    store.setItem(SOURCE_KEY, sourceEditor.value).catch(() => {
      storageNote.textContent = "Shell storage rejected the save; the rule remains in this session.";
    });
  }, 300);
}

async function loadIdentity() {
  const identity = window.napplet?.identity;
  if (!identity?.getPublicKey) {
    principal = undefined;
    setIdentity("No signer connected", "Following rules still work.", "The shell did not inject identity.");
    return;
  }
  try {
    principal = (await identity.getPublicKey()) || undefined;
    if (principal) {
      let profile = null;
      try {
        profile = await identity.getProfile();
      } catch {
        profile = null;
      }
      const name = profile?.displayName || profile?.name || profile?.nip05 || shortKey(principal);
      setIdentity(name, shortKey(principal), principal);
    } else {
      setIdentity("No signer connected", "Mentions rules need a signer.", "identity.getPublicKey returned empty.");
    }
  } catch (error) {
    principal = undefined;
    setIdentity("Identity unavailable", error.message, error.message);
  }
  try {
    identitySubscription = identity.onChanged((next) => {
      principal = next || undefined;
      if (principal) {
        setIdentity(shortKey(principal), shortKey(principal), principal);
      } else {
        setIdentity("No signer connected", "Mentions rules need a signer.", "");
      }
      if (running) stopSubscription("Signer changed. Activate the rule again.");
      checkSource();
    });
  } catch {
    identitySubscription = undefined;
  }
}

function wireEvents() {
  activateButton.addEventListener("click", () => activate());
  stopButton.addEventListener("click", () => stopSubscription());
  presetSelect.addEventListener("change", () => loadPreset(presetSelect.value));
  sourceEditor.addEventListener("input", () => {
    clearTimeout(checkTimer);
    checkTimer = setTimeout(() => checkSource(), 250);
    persistSource();
  });
  for (const tab of tabs) {
    tab.addEventListener("click", () => selectFilter(tab.dataset.filter));
  }
  window.addEventListener("pagehide", () => {
    stopSubscription("Applet closed.");
    try {
      identitySubscription?.close?.();
    } catch {
      // A closed identity subscription is not a user-facing failure.
    }
  }, { once: true });
}

async function boot() {
  wireEvents();
  clearFeed();
  selectFilter("all");
  try {
    compiler = await loadWasmBytes(compilerBytes);
    lensHost = createNScriptNapplet({
      napplet: window.napplet,
      compiler,
      capabilityCeiling: ["outbox", "identity", "storage"],
    });
  } catch (error) {
    setStatus(error?.message ?? "Could not load the NScript runtime.", "error");
    compileState.textContent = "Runtime unavailable";
    return;
  }
  await loadIdentity();
  await restoreSource();
  const available = lensHost.available;
  setStatus(
    available ? (principal ? "Shell connected" : "Shell connected · no signer") : "Waiting for outbox",
    available ? "active" : "error",
  );
  if (!available) {
    compileState.textContent = "outbox unavailable · activation disabled";
  }
}

void boot();
