// The FROST library built for the web (wasm-bindgen --target web, from ../../frost), handed
// to the server core before anything signs (../../server/wasm.ts).
import * as frost from '../frost-wasm/cosign_frost.js';
// @ts-ignore: Wrangler turns a .wasm import into a WebAssembly.Module.
import wasmModule from '../frost-wasm/cosign_frost_bg.wasm';
import { useWasm } from '../../server/wasm.ts';

frost.initSync({ module: wasmModule });
useWasm(frost);
