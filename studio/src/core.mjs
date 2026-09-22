// Pure panel logic for NScript Studio. Everything here is DOM-free so the node
// test harness (tests/core.test.mjs) can exercise it against the real wasm.

export const CATEGORY_ORDER = [
  "Nostr",
  "Network",
  "Payments",
  "Storage",
  "Secrets",
  "System",
];

const STATUS_ICONS = { granted: "✓", requested: "⚠", forbidden: "✗" };

export function statusIcon(status) {
  return STATUS_ICONS[status] ?? "?";
}

// Turns a wasm `footprint` response into an ordered, icon-decorated group list,
// plus tallies for the "requests / does not request" summary.
export function mapFootprint(footprint) {
  const groups = CATEGORY_ORDER.map((name) => {
    const group = (footprint?.groups ?? []).find((group) => group.name === name);
    return {
      name,
      items: (group?.items ?? []).map((item) => ({
        label: item.label,
        permission: item.permission ?? null,
        status: item.status,
        icon: statusIcon(item.status),
      })),
    };
  }).filter((group) => group.items.length > 0);
  const requested = [];
  const forbidden = [];
  for (const group of groups) {
    for (const item of group.items) {
      if (item.status === "requested") requested.push(item);
      else if (item.status === "forbidden") forbidden.push(item);
    }
  }
  return { groups, requested, forbidden };
}

// `nscript` diagnostics are byte spans with 1-based line/column. Monaco markers
// want 1-based line/column ranges; the column is the first byte of the span.
export function diagnosticsToMarkers(diagnostics) {
  return (diagnostics ?? []).map((diagnostic) => ({
    startLineNumber: diagnostic.line,
    startColumn: diagnostic.column,
    endLineNumber: diagnostic.line,
    endColumn: diagnostic.column + 1,
    message: `${diagnostic.code}: ${diagnostic.message}`,
    severity: 8, // MarkerSeverity.Error
  }));
}

// Synthetic events a Studio "Test Event" can inject, keyed to the handler
// event types the modules declare.
export function fixtures() {
  return [
    {
      name: "Note",
      event: {
        event_type: "Note",
        kind: 1,
        content: "hello, nostr",
        signer: "npub1abc",
        id: "note-1",
      },
    },
    {
      name: "NIP-17 DM",
      event: {
        event_type: "PrivateMessage",
        kind: 1059,
        content: "hi there",
        signer: "npub1abc",
        id: "dm-1",
      },
    },
    {
      name: "Reaction",
      event: {
        event_type: "Reaction",
        kind: 7,
        content: "+",
        tags: [["e", "note-1"]],
        signer: "npub1abc",
        id: "reaction-1",
      },
    },
    {
      name: "Zap",
      event: {
        event_type: "ZapRequest",
        kind: 9734,
        content: "",
        tags: [["p", "npub1abc"]],
        signer: "npub1abc",
        id: "zap-1",
      },
    },
    {
      name: "Concord message",
      event: {
        event_type: "StreamMessage",
        kind: 1059,
        content: "hello channel",
        signer: "npub1abc",
        id: "cord-1",
      },
    },
    {
      name: "Relay event",
      event: {
        event_type: "RelayStatus",
        kind: 30166,
        content: "",
        signer: "npub1abc",
        id: "relay-1",
      },
    },
  ];
}

// The New Script gallery. Each template checks clean with the current compiler.
export function templates() {
  return [
    {
      name: "Auto-reply bot",
      description: "Answers NIP-17 private messages matching a rule.",
      source: `use nip17

permissions {
    private_message
    relay public
    log
}

on PrivateMessage {
    if event.content contains "hello" {
        print("replying to " + event.author)
        nip17.send_private(PrivateMessage { recipient: event.author; content: "Hi!" })
    }
}
`,
    },
    {
      name: "Keyword monitor",
      description: "Watches notes for a keyword and logs matches.",
      source: `use nip01

permissions {
    read Note from public
    relay public
    log
}

on Note {
    if event.content contains "nostrhost" {
        print("found: " + event.content)
    }
}
`,
    },
    {
      name: "Bookmark to Nostr",
      description: "Reposts an event as a quick bookmark.",
      source: `use nip18

permissions {
    repost
}

repost "event-to-repost"
`,
    },
    {
      name: "Scheduled post",
      description: "Publishes a note on a schedule.",
      source: `use nip01

relayset public = configured
signer account = nip46()

defaults {
    signer: account
    relays: public
}

permissions {
    publish Note to public
    sign Note with account
    relay public
    clock
}

every 1h {
    publish Note { content: "Daily pulse from my NScript schedule" }
}
`,
    },
    {
      name: "Relay monitor",
      description: "Publishes periodic relay health checks.",
      source: `use nip66

permissions {
    relay_monitor
    relay public
    clock
}

every 30m {
    nip66.publish_relay_status(RelayStatus { relay: "wss://relay.ditto.pub"; uptime: 99.5; latency: 120 })
}
`,
    },
    {
      name: "NIP-46 policy",
      description: "Provisions a remote signer session.",
      source: `use nip46

signer account = nip46()
relayset public = configured

defaults {
    signer: account
    relays: public
}

permissions {
    sign Note with account
    relay public
}

let session = account.provision("bunker://signer.example.com")
`,
    },
    {
      name: "Concord moderation bot",
      description: "Kicks authors whose messages match a rule.",
      source: `use concord04

permissions {
    concord_kick
    log
}

on Note {
    if event.content contains "spam" {
        kick event.author
    }
}
`,
    },
    {
      name: "Blossom uploader",
      description: "Uploads a content-addressed blob.",
      source: `use nipb7

permissions {
    blossom
    log
}

upload "file://photo.jpg" hash "abc123" size 1024
`,
    },
    {
      name: "Empty script",
      description: "Start from scratch.",
      source: "",
    },
  ];
}

// Renders a simulated event report the way the dry-run panel wants it.
export function describeReport(report) {
  const lines = [
    `Matched: ${report.dispatched}/${report.subscriptions.length} handlers`,
  ];
  for (const subscription of report.subscriptions) {
    lines.push(`subscription ${subscription}`);
  }
  for (const record of report.logs ?? []) {
    lines.push(`log ${record.level}: ${record.message}`);
  }
  for (const call of report.operations ?? []) {
    lines.push(
      `${call.simulated ? "simulated" : "ran"} ${call.module}.${call.operation}(${(call.arguments ?? []).join(", ")})`,
    );
  }
  for (const [key, value] of Object.entries(report.storage ?? {})) {
    lines.push(`storage ${key} = ${value}`);
  }
  for (const failure of report.failures ?? []) {
    lines.push(`handler ${failure.handler} failed: ${failure.error}`);
  }
  return lines.join("\n");
}

// The Build checklist. `build` is the wasm `manifest` response (which also
// carries the compiled wasm and the lockfile request is separate).
export function buildChecklist(build) {
  const clean = build?.checked === true;
  const steps = [
    { step: "Source", ok: clean },
    { step: "Type check", ok: clean },
    { step: "Permissions", ok: clean },
    { step: "WASM build", ok: clean && build?.bytes > 0 },
    { step: "Lockfile", ok: clean },
    { step: "Manifest", ok: clean && build?.manifest != null },
  ];
  return steps;
}

export function decodeBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Renders the deterministic IR the way the lowering inspector wants it: the
// capability surface, the declared permissions, and the create → sign →
// publish operation chain.
export function describeIr(ir) {
  const lines = [`schema ${ir.schema}`, `profile ${ir.profile}`];
  for (const capability of ir.capabilities ?? []) {
    lines.push(`capability ${capability.kind}:${capability.name}`);
  }
  for (const permission of ir.permissions ?? []) {
    lines.push(`permission ${permission}`);
  }
  for (const operation of ir.operations ?? []) {
    lines.push(describeIrOperation(operation));
  }
  return lines.join("\n");
}

function describeIrOperation(operation) {
  switch (operation.op) {
    case "create_event":
      return `create_event(${operation.event}, kind ${operation.kind})`;
    case "sign_event":
      return `sign_event(${operation.event}, ${operation.signer})`;
    case "publish_event":
      return `publish_event(${operation.event}, ${operation.relayset})`;
    default:
      return JSON.stringify(operation);
  }
}