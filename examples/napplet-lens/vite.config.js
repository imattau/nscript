import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { nip5aManifest } from "@napplet/vite-plugin";
import requirements from "./nscript-napplet.json";

const wasmPath = fileURLToPath(
  new URL("../../target/wasm32-unknown-unknown/wasm-release/nscript_wasm.wasm", import.meta.url),
);
const virtualId = "virtual:nscript-compiler-wasm";

function compilerWasmPlugin() {
  return {
    name: "nscript-compiler-wasm",
    resolveId(id) {
      return id === virtualId ? `\0${virtualId}` : undefined;
    },
    load(id) {
      if (id !== `\0${virtualId}`) return undefined;
      let bytes;
      try {
        bytes = readFileSync(wasmPath);
      } catch {
        throw new Error("NScript WASM is missing; run `npm run wasm` first.");
      }
      return `export default ${JSON.stringify(bytes.toString("base64"))};`;
    },
  };
}

export default defineConfig({
  plugins: [
    compilerWasmPlugin(),
    nip5aManifest({
      nappletType: "nscript-lens",
      title: "NScript Lens",
      description: "A programmable, shell-mediated lens for mentions and feeds, driven by checked NScript rules.",
      requires: requirements.requires,
      optional: requirements.optional ?? ["identity", "storage"],
      artifactMode: "single-file",
    }),
  ],
  build: {
    target: "es2022",
    modulePreload: { polyfill: false },
    chunkSizeWarningLimit: 2000,
  },
});
