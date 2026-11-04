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

test('review 8 M1: a server can\'t block a peer by naming it in its challenge, nor by a duplicate entry', async () => {
  const { acc, H, stop } = await stopped();
  const [s0, , s2] = acc.servers;
  // S2 answers its challenge claiming to be S0: the device labels by the seat it asked, so nothing breaks.
  const real = s2.handle.bind(s2);
  s2.handle = async (from: string, body: any, at: number) => { const a = await real(from, body, at); return body.type === 'challenge' ? { ...a, server: s0.host.pub } : a; };
  for (const a of await acc.A.resumeHelper([stop], { paper: acc.paper })) assert.equal(a.kind, 'helper_resumed');
  s2.handle = real;
  assert.ok(verifyEvent(await H.sign({ content: 'resumed' })));
  // An extra entry naming S0 with a challenge S0 never issued: S0 takes its own and ignores the other.
  const b = msg('helper_resume', acc.g, acc.epochId, 'member', { ids: [stop] });
  const c = await challenge(acc, acc.paper, s0);
  const ap = approvePaperRequest(acc.g, what.request('helper_resume', b.id, b), acc.A.kp, acc.paper, [{ server: s0.host.pub, challenge: 'ff'.repeat(32) }, { server: s0.host.pub, challenge: c.challenge }]);
  assert.equal((await acc.bus.send(acc.A.kp, s0.kp.pub, { ...b, approval: ap })).kind, 'helper_resumed');
});

test('review 8 L5 and L6: a deleted for another epoch proves nothing; a lying server\'s deleted is not counted', async () => {
  const { verifyDeleted, deletedDigest } = await import('../src/requests.ts');
  const { schnorrSign } = await import('../src/event.ts');
  const acc = await create();
  const S1 = acc.servers[1];
  // S1 keeps the account and answers a host-signed deleted over a forged request of its own.
  const forged = { ...msg('account_delete', acc.g, acc.epochId, 'member', {}), approval: { lock: { member: acc.A.kp.pub, assertion: { authData: '', clientData: '', sig: '' } } } };
  S1.handle = async () => ({ type: 'deleted', request: forged, changes: [], host: S1.host.pub, host_sig: schnorrSign(deletedDigest(acc.g, forged), S1.host.sk) });
  acc.bus.kill(acc.servers[2].kp.pub);
  assert.equal(await acc.A.deleteAccount(), 1, 'only S0\'s proof counts');
  assert.ok(!acc.A.wiped, 'one proof is not two: the device keeps its copy and goes on sending');
  const ans = acc.servers[0].deletedAnswer();
  assert.ok(verifyDeleted(acc.A.m!, acc.g, ans));
  const other = { ...ans.request, epoch: 'ab'.repeat(16) };
  assert.equal(verifyDeleted(acc.A.m!, acc.g, { ...ans, request: other, host_sig: schnorrSign(deletedDigest(acc.g, other), acc.servers[0].host.sk) }), false, 'another epoch, properly host-signed');
});
