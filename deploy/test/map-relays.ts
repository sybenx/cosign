// For the test only: connect to a relay's "public" address at another one, e.g.
// TEST_RELAY_MAP="wss://strfry.sidecar-test.example=ws://localhost:17777", the way the
// servers do with COSIGN_RELAY_MAP. Load it before nostr-tools (`node --import`): it
// takes the WebSocket it finds when it loads. The map is read at each connect.

const norm = (u: string) => u.trim().replace(/\/+$/, '').toLowerCase();
const target = (url: string) => {
  for (const x of (process.env.TEST_RELAY_MAP ?? '').split(',')) {
    const [from, to] = x.split('=', 2);
    if (to && norm(from) === norm(url)) return to.trim();
  }
  return url;
};
const Real = globalThis.WebSocket;
globalThis.WebSocket = class extends Real {
  constructor(url: string | URL, protocols?: string | string[]) { super(target(String(url)), protocols); }
} as typeof WebSocket;
