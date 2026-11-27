import wasmBase64 from "virtual:nscript-compiler-wasm";

export default Uint8Array.from(atob(wasmBase64), (character) => character.charCodeAt(0));
