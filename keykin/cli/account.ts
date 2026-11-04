// A throwaway Keykin account on this laptop, for a dry run against local or test servers only (never a live one):
// the laptop is the account's first device, made by DKG through the test servers' front doors (Account admin §1.1),
// and it invites a phone. State is kept in `--dir` (device.json: the device's snapshot, with a soft lock, test only;
// paper.txt: the backup key's 24 words, printed once).
//
//   node cli/account.ts create --dir D --relays ws://127.0.0.1:17771,ws://127.0.0.1:17772 --fronts <host>,<host>,<host>
//   node cli/account.ts invite --dir D [--app-relays ws://10.0.2.2:17771,…]   prints a code; type the phone's 6 digits
//   node cli/account.ts run --dir D [--seconds N]                               stays online: catches up every 30 s
//   node cli/account.ts show --dir D
//
// The host keys (`--fronts`) are what each server prints at start (`{"started", "host"}`, e.g. `docker compose logs`).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { RelayNet } from '../runtime/relay.ts';
import { createByDkg } from '../sim/account.ts';
import { DeviceNode } from '../device/node.ts';
import { Inviter } from '../src/join.ts';
import { pickSalt } from '../src/codes.ts';
import { takenIndices } from '../src/membership.ts';
import { backupWords } from '../src/backup.ts';
import { msg } from '../src/msg.ts';
import { nip19 } from 'nostr-tools';
import type { Change } from '../src/types.ts';

/** Live hosts this tool never talks to (the user's production servers and relays). */
const LIVE = /(^|\.)syb\.lol$|(^|\.)aaro\.cc$|racknerd/i;
function arg(name: string, need = true): string {
  const k = process.argv.indexOf(`--${name}`);
  const v = k > 0 ? process.argv[k + 1] : undefined;
  if (!v && need) { console.error(`--${name} is needed`); process.exit(2); }
  return v ?? '';
}
const list = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);
function testOnly(urls: string[]) {
  for (const u of urls) {
    let host = ''; try { host = new URL(u).hostname; } catch { console.error(`not a URL: ${u}`); process.exit(2); }
    if (LIVE.test(host)) { console.error(`refused: ${host} is a live server; this tool is for test servers only`); process.exit(2); }
  }
}
const out = (x: object) => console.log(JSON.stringify(x));

async function open(dir: string) {
  const conf = JSON.parse(readFileSync(join(dir, 'account.json'), 'utf8'));
  testOnly(conf.relays);
  const net = new RelayNet({ relays: conf.relays, timeoutMs: 9000, resendMs: 1500 });
  await net.connect();
  const d = net.add(DeviceNode.restore(net as any, readFileSync(join(dir, 'device.json'), 'utf8')));
  d.attach({ save: (_k, text) => writeFileSync(join(dir, 'device.json'), text) });
  return { conf, net, d };
}

async function main() {
  const cmd = process.argv[2], dir = arg('dir');
  if (cmd === 'create') {
    if (existsSync(join(dir, 'device.json'))) { console.error(`${dir} already holds an account`); process.exit(2); }
    const relays = list(arg('relays')), fronts = list(arg('fronts'));
    testOnly(relays);
    if (fronts.length !== 3 || fronts.some((f) => !/^[0-9a-f]{64}$/.test(f))) { console.error('--fronts: three host keys (64 hex)'); process.exit(2); }
    mkdirSync(dir, { recursive: true });
    const net = new RelayNet({ relays, timeoutMs: 9000, resendMs: 1500 });
    await net.connect();
    const acc = await createByDkg({ net: net as any, fronts, relays });
    writeFileSync(join(dir, 'account.json'), JSON.stringify({ relays, g: acc.g, created: net.now }, null, 1));
    acc.A.attach({ save: (_k, text) => writeFileSync(join(dir, 'device.json'), text) });
    // The paper: the backup key's 24 words. A throwaway account's, but kept, so the paper drill can run on it.
    const words = backupWords(acc.paper.sk);
    writeFileSync(join(dir, 'paper.txt'), words.join(' ') + '\n', { mode: 0o600 });
    out({ created: nip19.npubEncode(acc.g), g: acc.g, device: acc.A.kp.pub, servers: acc.A.servers().map((s) => s.host), paper: join(dir, 'paper.txt') });
    console.log(`\nPaper (write it down; throwaway account):\n  ${words.join(' ')}\n`);
    net.close(); process.exit(0);
  }
  if (cmd === 'invite') {
    const { conf, net, d } = await open(dir);
    await d.fetch();
    const appRelays = arg('app-relays', false) ? list(arg('app-relays')) : conf.relays;
    testOnly(appRelays);
    d.inviter = new Inviter({ g: d.g, m: d.kp.pub, now: net.now });
    out({ invite: d.inviter.invite(appRelays) });
    console.error('Type the 6 digits the phone shows, then Enter:');
    const typed = await new Promise<string>((res) => createInterface({ input: process.stdin }).once('line', (l) => res(l.trim())));
    if (!d.inviter.typed(typed)) { out({ error: 'check_mismatch' }); net.close(); process.exit(1); }
    // Add the new device with this one's lock, repair its indices with a server, and welcome it (core §4.1–§4.4).
    const n = d.inviter.accepted!.n;
    const { salt, indices } = pickSalt(d.g, d.epochId, n, takenIndices(d.m!));
    const add: Change[] = [{ add: { key: n, kind: 'device', lock: null, salt } }];
    await d.submit(add, d.approveLock(add));
    const s0 = d.servers()[0];
    for (const i of indices)
      for (const w of await d.repairFor([{ key: d.kp.pub, indices: [...d.state!.shares.keys()] }, { key: s0.key, indices: s0.shares }], i, n, 'add'))
        await net.events.publishEvent(w);
    const a = await net.send(d.kp, n, msg('welcome', d.g, d.epochId, 'member', { record: d.recEv, changes: d.changes, state: [...d.state!.ids], base_dk: d.baseDk, dk: d.dkSeeds }));
    out({ added: n, welcomed: a?.type === 'ack', state: d.dataKeys.current().state });
    net.close(); process.exit(a?.type === 'ack' ? 0 : 1);
  }
  if (cmd === 'run') {
    const { net, d } = await open(dir);
    const until = Date.now() + (Number(arg('seconds', false)) || 3600) * 1000;
    out({ running: d.kp.pub, account: nip19.npubEncode(d.g) });
    while (Date.now() < until) {
      try { await d.fetch(); out({ at: net.now, state: d.dataKeys.current().state, devices: d.memberKeys().length, notices: d.notices.length }); } catch (e) { out({ error: (e as Error).message }); }
      await new Promise((r) => setTimeout(r, 30_000));
    }
    net.close(); process.exit(0);
  }
  if (cmd === 'show') {
    const { net, d } = await open(dir);
    await d.fetch().catch(() => {});
    out({ account: nip19.npubEncode(d.g), device: d.kp.pub, devices: d.memberKeys(), servers: d.servers().map((s) => s.host), state: d.dataKeys.current().state, grants: d.grants.all().length });
    net.close(); process.exit(0);
  }
  console.error('commands: create, invite, run, show (see the head of cli/account.ts)'); process.exit(2);
}
await main();
