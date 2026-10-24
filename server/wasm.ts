// The FROST library (frost-wasm, built from ../frost) wherever this code runs: Node loads
// its build from here on first use; a Cloudflare Worker hands in its own build first
// (worker/src/wasm.ts, with useWasm), so nothing here touches Node there.

let impl: any = null;

/** For a host with its own build of the library (the Worker's, for the web). */
export function useWasm(w: any) { impl = w; }

const load = () => (globalThis as any).process.getBuiltinModule('module').createRequire(import.meta.url)('./frost-wasm/cosign_frost.js');

/** The library's functions, as frost/src/wasm.rs exports them. */
export const W: any = new Proxy({}, { get: (_t, k) => (impl ??= load())[k] });
