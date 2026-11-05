// The browser self-test (browser/build.mjs → dist/selftest.html): the bundled device with the web FROST, run in a real
// browser on the in-memory network: an account made with servers, a sign, a second device invited, the first reported
// lost with the paper, the paper checked. It writes one JSON result to the page and to `window.keykinSelftest`.
import init, * as frost from '../frost-wasm-web/keykin_frost.js';
import { useWasm, backupWords, readBackupWords } from './index.ts';
import { create, invite } from '../sim/account.ts';
import { verifyEvent } from '../src/event.ts';
import type { Change } from '../src/types.ts';

async function run() {
  const t0 = performance.now();
  await init(new URL('./keykin_frost_bg.wasm', import.meta.url));
  useWasm(frost);
  const acc = await create();
  const A = acc.A;
  const ev = await A.sign({ kind: 1, content: 'signed in a browser', tags: [] });
  const B = await invite(acc, A, (l) => A.approveLock(l), { lock: true });
  await B.fetch();
  const list: Change[] = [{ remove: A.kp.pub }, { redeal: { dealer: B.kp.pub } }];
  await B.submit(list, B.approveLock(list));
  await A.fetch();
  const ev2 = await B.sign({ kind: 1, content: 'after the redeal', tags: [] });
  const words = backupWords(acc.paper.sk);
  const paper = readBackupWords(words);
  return { ok: true, userAgent: navigator.userAgent, signed: verifyEvent(ev) && ev.pubkey === acc.g, laptopRemoved: A.wiped, signedAfter: verifyEvent(ev2) && ev2.pubkey === acc.g,
    paperRoundTrip: Array.from(paper).join() === Array.from(acc.paper.sk).join(), ms: Math.round(performance.now() - t0) };
}
run().then((r) => r, (e) => ({ ok: false, error: String(e?.stack ?? e) })).then((r) => {
  (globalThis as any).keykinSelftest = r;
  document.body.textContent = JSON.stringify(r);
});
