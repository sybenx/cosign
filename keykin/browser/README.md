# keykin/device in the browser

The extension's member (Doors §3.1) is `keykin/device` bundled for the browser, with FROST built for the web.

1. **FROST for the web** (once, and after any change in `frost/`):

       (cd frost && cargo build --release --target wasm32-unknown-unknown --features wasm)
       wasm-bindgen --target web --out-dir frost-wasm-web frost/target/wasm32-unknown-unknown/release/keykin_frost.wasm

2. **The bundle:** `node browser/build.mjs` writes `dist/keykin-device.js` (ESM) and `dist/keykin_frost_bg.wasm`. It fails if anything on the device's path imports a Node module. `test/browser-bundle.test.ts` runs it.

3. **In a real browser:** `node browser/serve.mjs` serves `dist/` on http://127.0.0.1:8765. The self-test page makes an account on the in-memory network, signs, invites a second device, reports the first lost with a redeal, signs again and reads the paper back. It writes one JSON result to the page and to `window.keykinSelftest`.

**In the extension:**

    import init, * as frost from './keykin_frost.js';   // frost-wasm-web
    import { useWasm, DeviceNode, RelayNet } from './keykin-device.js';
    await init(wasmUrl); useWasm(frost);

Then: a `RelayNet` over the account's relays, `DeviceNode.restore(net, saved)` or a join, and `attach({ save })` with the extension's encrypted-at-rest store. The manifest's CSP already allows `wasm-unsafe-eval`.
