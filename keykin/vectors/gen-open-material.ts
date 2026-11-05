// A paper opened at a recovery (core §6.5 step 4, 14.21), by the TS reference: a simulated account goes through two
// redeals (a device reported lost, then a plain redeal), the paper holder waits and collects the servers' release bundles, and
// this file records exactly what `openMaterial` takes and what it returns. Every port opens the same to the same.
// Run: node vectors/gen-open-material.ts > vectors/open-material.json
import { create, invite } from '../sim/account.ts';
import { PaperHolder } from '../device/node.ts';
import { openMaterial, materialInner } from '../src/upkeep.ts';
import { itemHash } from '../src/redeal.ts';
import { checkEpochRecord } from '../src/record.ts';
import { computeMembership } from '../src/membership.ts';
import { commitmentFrom, scalarHex } from '../src/curve.ts';
import { bytesToHex, hexToBytes, shaHex } from '../src/bytes.ts';
import type { Change } from '../src/types.ts';

const acc = await create();
const B = await invite(acc, acc.A, (l) => acc.A.approveLock(l));
const list: Change[] = [{ remove: B.kp.pub }, { redeal: { dealer: acc.A.kp.pub } }];
await acc.A.submit(list, acc.A.approveLock(list));
const again: Change[] = [{ redeal: { dealer: acc.A.kp.pub } }];
await acc.A.submit(again, acc.A.approveLock(again));
const servers = acc.servers.map((s) => s.kp.pub);
const P = new PaperHolder(acc.bus, acc.paper, acc.g, acc.epochId, servers);
acc.bus.add(P);
await P.start(servers);
acc.bus.advance(3 * 86400 + 1);
const r = await P.collect(servers);
// The inputs exactly as `collect` builds them.
const bs = [...P.bundles.values()];
const rec = checkEpochRecord(bs[0].record, { g: acc.g });
const m = computeMembership(rec, r.changes);
const pc = m.accepted.find((p) => p.type === 'paper' && (p.c.change as any).paper.key === acc.paper.pub);
const pin = pc ? (pc.c.change as any).paper.inner : rec.backup;
const baseSeed = pc ? r.seeds.get([...m.redeals.values()].find((x) => x.listHash === pc.listHash)!.r.id)! : r.seeds.get('base')!;
const items = [...new Map(bs.flatMap((b) => b.items).map((it: any) => [itemHash(it), it])).values()];
const seedIts = ((bs.find((b) => b.base && materialInner(b.base, (b.items ?? []).filter((x: any) => x.kind === 'seeds')) === pin) ?? bs[0]).items ?? []).filter((x: any) => x.kind === 'seeds');
const input = { g: acc.g, K_sk: bytesToHex(acc.paper.sk), pin, base: r.base, base_seed: baseSeed, items, seeds: [...r.seeds], seed_items: seedIts,
  C0: rec.commitment, redeals: [...m.redeals.values()].map((x) => x.r), state: [...r.state].sort() };
const o = openMaterial({ g: acc.g, backup: acc.paper, pin, base: r.base, baseSeed, items, seeds: r.seeds, seedItems: seedIts,
  C0: commitmentFrom(rec.commitment), redeals: [...m.redeals.values()].map((x) => x.r), state: r.state });
console.log(JSON.stringify({
  note: 'openMaterial(input) must give out: the backup seat shares (index → scalar hex), the base dk, and the dk seeds (as sha256, sorted)',
  input,
  out: { shares: [...o.shares].map(([i, s]) => [i, scalarHex(s)]), dk: o.dk, dk_seed_hashes: o.dkSeeds.map((x) => shaHex(hexToBytes(x))).sort(), redeals_in_state: r.state.size },
}, null, 1));
process.exit(0);
