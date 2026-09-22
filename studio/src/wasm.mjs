// Thin JSON-in/JSON-out client over the `nscript_wasm` ABI. The same module is
// used by the browser (via `fetch`) and by the node test harness (via a file
// read), so the glue is exercised in CI without a browser.

export function createClient(instance) {
  const {
    memory,
    nscript_abi,
    nscript_alloc,
    nscript_dealloc,
    nscript_handle,
    nscript_free,
  } = instance.exports;

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

  return {
    abi: nscript_abi(),
    analyze(source, modules = []) {
      return call({ op: "analyze", source, modules });
    },
    footprint(source, modules = []) {
      return call({ op: "footprint", source, modules });
    },
    inspect(source, modules = []) {
      return call({ op: "inspect", source, modules });
    },
    completions(source, offset, modules = []) {
      return call({ op: "completions", source, offset, modules });
    },
    hover(source, offset, modules = []) {
      return call({ op: "hover", source, offset, modules });
    },
    symbols(source, modules = []) {
      return call({ op: "symbols", source, modules });
    },
    testEvent(source, event, principal = undefined, modules = []) {
      return call({ op: "test_event", source, event, principal, modules });
    },
    compile(source, modules = []) {
      return call({ op: "compile", source, modules });
    },
    ir(source, modules = []) {
      return call({ op: "ir", source, modules });
    },
    run(source, modules = []) {
      return call({ op: "run", source, modules });
    },
    manifest(source, publisher, name = "script", version = "0.1.0", modules = []) {
      return call({ op: "manifest", source, publisher, name, version, modules });
    },
    lock(source, modules = []) {
      return call({ op: "lock", source, modules });
    },
  };
}

export async function loadWasm(url) {
  const bytes = await (await fetch(url)).arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return createClient(instance);
}