# keykin: Keykin Core reference implementation (TypeScript)

The core of [`docs/keykin/core.md`](../docs/keykin/core.md) (draft 13.3), test-first. It is separate
from Cosign 0.12: nothing in `server/`, `site/`, `worker/` or `frost/` is changed or imported, and
no live server is involved. Modules (Server profile, Device policy, Doors and grants, Backup,
Account admin, Helper, Key families) are not implemented.

```bash
npm install
npm test          # every test, including the relay e2e if `nak` is installed (~35 s)
npx tsc -p .      # typecheck
```

## Layout

| Path | What |
|---|---|
| `frost/` | A small Rust crate over ZF `frost-secp256k1-tr` 2.2: 32-byte identifiers (§3.2), groups named by their commitment `C_S`, hedged nonces (§5.2), repair. Built to `frost-wasm/`. |
| `src/` | The pure core: no I/O, clock passed in. |
| `sim/` | In-process simulation: devices, servers and the paper holder on an in-memory bus that carries real NIP-59 wraps. |
| `runtime/relay.ts` | The same nodes over real relays (kind 21059, parts, re-send). Tested only against local `nak serve` relays. |
| `test/` | `vectors.test.ts` (every computed vector in `vectors.json`), unit tests per area, `sim.test.ts` (end-to-end flows), `relay.e2e.test.ts`. |
| `BEHAVIOUR.md` | The expected outcome of each behaviour case in `vectors.md`, with the test that checks it. |

`src/` by spec section: `codes.ts` (every hash-derived value), `curve.ts`, `frost.ts`,
`record.ts` (§3.1, §3.3, §3.4), `membership.ts` (§3.2, §6.7.2, order-free), `approval.ts` and
`lock.ts` (§6.1, §6.2), `coordinator.ts` and `cosigner.ts` (§5, §6.3, §6.5), `ecdh.ts` (§5.5),
`destructive.ts` (§5.7 item 4, §5.8), `lifetimes.ts` (§5.3, §5.6), `join.ts` and `repair.ts`
(§4), `redeal.ts` and `upkeep.ts` (§6.7, §7.2), `transport.ts` (§9), `inbox.ts` (§8).

## Rebuilding the wasm

```bash
cd frost
export RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/src"
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target nodejs --out-dir ../frost-wasm --out-name keykin_frost target/wasm32-unknown-unknown/release/keykin_frost.wasm
echo '{"type":"commonjs"}' > ../frost-wasm/package.json
```

## Where the spec left a choice

Wire encodings the spec doesn't fix yet (approval fields, how a change names its list, `pair`
bodies, the `ecdh_partial` shape, …) went to the spec session as numbered issues. The choices
made here are interim and marked in the code where they appear.

## Not done

Paper re-issue, helper resumes by paper, Web Push
encryption (RFC 8291) and gateways, durable storage (`CoSigner.snapshot()`/`restore()` covers what
§5.6 requires a server to keep across restarts, but nothing writes it to disk yet), and the Kotlin build.
