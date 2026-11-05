// The FROST wasm module (keykin/frost), loaded once. In Node it is the `nodejs` build in
// ../frost-wasm, loaded on first use without a static `node:` import; a browser (the extension) builds
// keykin/frost with `--target web` and hands the initialised module to `useWasm` before any signing.

let mod: any = null;
export function useWasm(w: unknown) { mod = w; }
function load(): any {
  if (mod) return mod;
  const getBuiltin = (globalThis as any).process?.getBuiltinModule;
  if (!getBuiltin) throw new Error('keykin: call useWasm() with the FROST web build before signing');
  mod = getBuiltin('node:module').createRequire(import.meta.url)('../frost-wasm/keykin_frost.js');
  return mod;
}
/** The module's functions, loaded on first use. */
export const W: any = new Proxy({}, { get: (_t, p) => load()[p] });
