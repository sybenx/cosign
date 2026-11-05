// Core 14.26 §5.8: a held (destructive) event approved by a pair of devices instead of the lock or a 3-day hold.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { create, invite } from '../sim/account.ts';
import { detachedDigest, what } from '../src/codes.ts';
import { schnorrSign, verifyEvent, eventId, newKey } from '../src/event.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const code = async (f: () => unknown) => { try { await f(); return 'ok'; } catch (e: any) { return e.code ?? e.message; } };

test('a pair of current devices approves a held event; anything less is refused', async () => {
  const acc = await create();
  const A = acc.A;
  const B = await invite(acc, A, (l) => A.approveLock(l));
  // An empty follow list is destructive on its face (§5.8): a server wants an approval or a passed hold.
  const ev = { pubkey: acc.g, created_at: A.now, kind: 3, tags: [] as string[][], content: '' };
  assert.equal(await code(() => A.sign(ev)), 'needs_approval');
  const id = eventId(ev as any), r = bytesToHex(randomBytes(16));
  const d = detachedDigest('pair', acc.g, { what: bytesToHex(what.sign(id)), r });
  const pair = (x: any, y: any) => ({ pair: [{ member: x.kp.pub, sig: schnorrSign(d, x.kp.sk), r }, { member: y.kp.pub, code_sig: schnorrSign(d, y.kp.sk) }] }) as any;
  // The same device twice, a stranger, a requester outside the pair, a forged signature: refused.
  assert.equal(await code(() => A.sign(ev, { approval: pair(A, A) })), 'pair_same_device');
  const stranger = { kp: newKey() };
  assert.equal(await code(() => A.sign(ev, { approval: pair(A, stranger) })), 'approver_not_device');
  const C = await invite(acc, A, (l) => A.approveLock(l));
  assert.equal(await code(() => C.sign(ev, { approval: pair(A, B) })), 'needs_approval');
  const bad = pair(A, B); bad.pair[1].code_sig = schnorrSign(d, C.kp.sk);
  assert.equal(await code(() => A.sign(ev, { approval: bad })), 'bad_signature');
  // A 3-day hold already running for it at a server ends once that server co-signs it with the pair (14.26 item 7).
  const { msg } = await import('../src/msg.ts');
  const { holdWaitId } = await import('../src/codes.ts');
  for (const s of acc.servers) await acc.bus.send(A.kp, s.kp.pub, { ...msg('hold', acc.g, acc.epochId, 'member'), event: { ...ev, id } });
  assert.ok(acc.servers.every((s) => s.co!.holds.has(holdWaitId(id))), 'the holds started');
  // A and B together: signed.
  const signed = await A.sign(ev, { approval: pair(A, B) });
  assert.ok(acc.servers.some((s) => !s.co!.holds.has(holdWaitId(id))), 'the co-signing server ended its hold');
  assert.ok(verifyEvent(signed) && signed.pubkey === acc.g && signed.kind === 3);
});
