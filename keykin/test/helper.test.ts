// Helper module §3.2 "Resume helper" by the paper, and the shared paper-request approval (core §6.2):
// one device signature and the backup key's signature over every server's own challenge.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, addHelper } from '../sim/account.ts';
import { approvePaperRequest } from '../src/approval.ts';
import { verifyEvent, newKey } from '../src/event.ts';
import { what } from '../src/codes.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';
import { msg } from '../sim/nodes.ts';

async function stopped() {
  const acc = await create();
  const H = await addHelper(acc, acc.A, (l) => acc.A.approveLock(l));
  const stop = bytesToHex(randomBytes(16));
  for (const s of acc.servers) await acc.bus.send(acc.A.kp, s.kp.pub, msg('helper_stop', acc.g, acc.epochId, 'member', { stop, by: acc.A.kp.pub }));
  await assert.rejects(H.sign({ content: 'stopped?' }), /helper_stopped/);
  return { acc, H, stop };
}
const challenge = async (acc: any, from: any, s: any) => (await acc.bus.send(from, s.kp.pub, msg('challenge', acc.g, acc.epochId, 'ask')));

test('Helper §3.2: Resume helper by the paper, with a challenge from every server', async () => {
  const { acc, H, stop } = await stopped();
  const answers = await acc.A.resumeHelper([stop], { paper: acc.paper });
  assert.equal(answers.length, 3);
  for (const a of answers) assert.deepEqual([a.type, a.kind, a.stops], ['notice', 'helper_resumed', []]);
  assert.ok(verifyEvent(await H.sign({ content: 'resumed by the paper' })));
});

test('core §6.2 paper requests: each server checks its own challenge, once, by the current backup key and the sender', async () => {
  const { acc, stop } = await stopped();
  const send = (s: any, body: any, approval: any, from = acc.A.kp) => acc.bus.send(from, s.kp.pub, { ...body, approval });
  const body = () => msg('helper_resume', acc.g, acc.epochId, 'member', { ids: [stop] });
  const chs = async (from = acc.paper) => { const out = []; for (const s of acc.servers) { const c = await challenge(acc, from, s); out.push({ server: c.server, challenge: c.challenge }); } return out; };
  const [s0, s1] = acc.servers;
  // Only another server's challenge: this server has none of its own.
  { const b = body(); const c = await chs(); const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, acc.paper, c.filter((x) => x.server !== s0.host.pub));
    assert.equal((await send(s0, b, ap)).code, 'stale_challenge'); assert.equal((await send(s1, b, ap)).kind, 'helper_resumed'); }
  // A challenge used twice: the second request is refused.
  { const b = body(); const c = await chs(); const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, acc.paper, c);
    assert.equal((await send(s0, b, ap)).kind, 'helper_resumed');
    const b2 = body(); const ap2 = approvePaperRequest(acc.g, what.request('helper_resume', b2.id, b2), acc.A.kp, acc.paper, c);
    assert.equal((await send(s0, b2, ap2)).code, 'stale_challenge'); }
  // A challenge issued to someone else than the backup key.
  { const b = body(); const c = await chs(acc.A.kp); const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, acc.paper, c);
    assert.equal((await send(s0, b, ap)).code, 'stale_challenge'); }
  // A key that is not the current backup key.
  { const b = body(); const other = newKey(); const c = await chs(other); const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, other, c);
    assert.equal((await send(s0, b, ap)).code, 'not_current_backup'); }
  // The backup signature over another request's what.
  { const b = body(); const c = await chs(); const other = body(); const ap = approvePaperRequest(acc.g, what.request('helper_resume', other.id, other), acc.A.kp, acc.paper, c);
    assert.equal((await send(s0, b, ap)).code, 'bad_signature'); }
  // The old single-challenge shape is not a request approval.
  { const b = body(); const c = await chs(); const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, acc.paper, c);
    const { challenges, ...rest } = ap.paper; const single = { paper: { ...rest, challenge: challenges[0].challenge, server: challenges[0].server, backup_sig: challenges[0].backup_sig } };
    assert.equal((await send(s0, b, single)).code, 'malformed'); }
  // Approved by one device, sent by another.
  { const { invite } = await import('../sim/account.ts'); const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
    const b = body(); const c = await chs(); const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, acc.paper, c);
    assert.equal((await send(s0, b, ap, B.kp)).code, 'needs_approval'); }
});

test('Account admin §3: Destroy my key by the paper, in the same shape; a peer relays it to a server that missed it', async () => {
  const acc = await create();
  acc.bus.kill(acc.servers[2].kp.pub);
  const n = await acc.A.deleteAccount({ paper: acc.paper });
  assert.equal(n, 2);
  assert.ok(acc.A.wiped && acc.servers[0].tombstone && acc.servers[1].tombstone && !acc.servers[2].tombstone);
  acc.bus.revive(acc.servers[2].kp.pub);
  const ans = await acc.bus.send(acc.servers[0].kp, acc.servers[2].kp.pub, { ...(acc.servers[0].deletedAnswer()) });
  assert.equal(ans.type, 'deleted');
  assert.ok(acc.servers[2].tombstone);
});
