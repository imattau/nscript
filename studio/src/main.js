import * as monaco from "monaco-editor";
import { loadWasm } from "./wasm.mjs";
import {
  diagnosticsToMarkers,
  fixtures,
  mapFootprint,
  templates,
  describeReport,
} from "./core.mjs";

const status = document.getElementById("status");
const templateList = document.getElementById("template-list");
const permissionsPanel = document.getElementById("permissions-panel");
const problemsPanel = document.getElementById("problems-panel");
const fixtureSelect = document.getElementById("fixture");
const runPreview = document.getElementById("run-preview");
const previewOutput = document.getElementById("preview-output");

async function main() {
  const client = await loadWasm("./nscript_wasm.wasm").catch((error) => {
    status.textContent = `failed to load compiler: ${error}`;
    throw error;
  });
  status.textContent = `compiler abi ${client.abi}`;

  monaco.languages.register({ id: "nscript" });
  monaco.languages.setMonarchTokensProvider("nscript", {
    keywords: [
      "use", "runtime", "signer", "relayset", "relay", "key", "store", "defaults",
      "permissions", "publish", "on", "once", "every", "at", "send", "if", "for",
      "let", "fn", "match", "return", "kick", "ban", "say", "react", "zap",
      "reply", "repost", "search", "comment", "report", "label", "status",
      "draft", "badge", "highlight", "assert", "calendar", "live", "image",
      "video", "file", "upload", "handler",
    ],
    types: [
      "Bool", "Int", "Decimal", "Text", "Bytes", "Duration", "Percentage",
      "Unit", "Never", "List", "Set", "Map", "Option", "Result", "PubKey",
      "EventId", "Signature", "RelayUrl", "Timestamp", "Kind", "Nprofile",
      "Nevent", "Naddr", "Nsec", "Signer", "SecretKey", "Tag",
    ],
    operators: "+-*/%=<>!",
    tokenizer: {
      root: [
        [/[a-zA-Z_]\w*/, {
          cases: {
            "@keywords": "keyword",
            "@types": "type",
            "@default": "identifier",
          },
        }],
        [/\d+/, "number"],
        [/"/, { token: "string", next: "@string" }],
        [/\/\/.*$/, "comment"],
        [/[{}()[\];,]/, "delimiter"],
        [/@operators/, "operator"],
      ],
      string: [
        [/[^"]+/, "string"],
        [/"/, { token: "string", next: "@pop" }],
      ],
    },
  });

  monaco.languages.registerCompletionItemProvider("nscript", {
    triggerCharacters: [".", " "],
    provideCompletionItems(model, position) {
      const offset = model.getOffsetAt(position);
      const source = model.getValue();
      const response = client.completions(source, offset);
      if (!response.ok) {
        return { suggestions: [] };
      }
      const suggestions = response.result.completions.map((completion) => ({
        label: completion.label,
        kind: monaco.languages.CompletionItemKind[
          completion.kind === "keyword"
            ? "Keyword"
            : completion.kind === "module"
              ? "Module"
              : completion.kind === "type"
                ? "Class"
                : completion.kind === "operation"
                  ? "Function"
                  : completion.kind === "field"
                    ? "Field"
                    : "Variable"
        ],
        insertText: completion.insert,
        detail: completion.detail ?? undefined,
      }));
      return { suggestions };
    },
  });

  monaco.languages.registerHoverProvider("nscript", {
    provideHover(model, position) {
      const offset = model.getOffsetAt(position);
      const response = client.hover(model.getValue(), offset);
      if (!response.ok || !response.result.hover) {
        return null;
      }
      return {
        contents: [
          { value: `**${response.result.hover.label}**` },
          { value: response.result.hover.detail },
        ],
      };
    },
  });

  const editor = monaco.editor.create(document.getElementById("editor"), {
    value: templates()[0].source,
    language: "nscript",
    theme: "vs-dark",
    automaticLayout: true,
    minimap: { enabled: false },
  });

  for (const template of templates()) {
    const item = document.createElement("button");
    item.className = "template";
    item.textContent = template.name;
    item.title = template.description;
    item.addEventListener("click", () => {
      editor.setValue(template.source);
    });
    templateList.appendChild(item);
  }

  for (const fixture of fixtures()) {
    const option = document.createElement("option");
    option.value = JSON.stringify(fixture.event);
    option.textContent = fixture.name;
    fixtureSelect.appendChild(option);
  }

  function refresh() {
    const source = editor.getValue();
    const response = client.inspect(source);
    if (!response.ok) {
      problemsPanel.textContent = `request failed: ${response.error.message}`;
      return;
    }
    const { diagnostics, footprint } = response.result;
    monaco.editor.setModelMarkers(
      editor.getModel(),
      "nscript",
      diagnosticsToMarkers(diagnostics),
    );

    if (diagnostics.length === 0) {
      problemsPanel.textContent = "no problems";
    } else {
      problemsPanel.innerHTML = "";
      for (const diagnostic of diagnostics) {
        const line = document.createElement("div");
        line.className = `problem problem-${diagnostic.severity ?? "error"}`;
        line.textContent = `${diagnostic.code}:${diagnostic.line}:${diagnostic.column} ${diagnostic.message}`;
        problemsPanel.appendChild(line);
      }
    }

    const mapped = mapFootprint(footprint);
    permissionsPanel.innerHTML = "";
    for (const group of mapped.groups) {
      const heading = document.createElement("div");
      heading.className = "group";
      heading.textContent = group.name;
      permissionsPanel.appendChild(heading);
      for (const item of group.items) {
        const row = document.createElement("div");
        row.className = `item item-${item.status}`;
        row.textContent = `${item.icon} ${item.label}`;
        row.title = item.permission ?? "";
        permissionsPanel.appendChild(row);
      }
    }
    if (mapped.groups.length === 0) {
      permissionsPanel.textContent = "no capabilities inferred";
    }
  }

  let timer;
  editor.onDidChangeModelContent(() => {
    clearTimeout(timer);
    timer = setTimeout(refresh, 200);
  });

  runPreview.addEventListener("click", () => {
    const event = JSON.parse(fixtureSelect.value);
    const response = client.testEvent(editor.getValue(), event);
    if (!response.ok) {
      previewOutput.textContent = `request failed: ${response.error.message}`;
      return;
    }
    const { report } = response.result;
    previewOutput.textContent = report ? describeReport(report) : "no preview";
  });

  refresh();
}

main();