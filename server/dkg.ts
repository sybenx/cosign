// Making a key with nobody ever holding it (DKG), for a weighted group: your phone runs
// 3 of the shares, each server 1, and it takes `threshold` (4) to sign. Every holder
// runs the library's three parts for each of its shares (frost/src/lib.rs), sending
// part-1 packages to everyone and part-2 packages to each share's holder, over the
// same sealed member messages as everything else. Packages are re-sent until the run
// is done, since relays drop things; a repeat is ignored.
//
// The same runner is used by the servers and the test phone; the app has its own copy.

import { createRequire } from 'node:module';

const W = createRequire(import.meta.url)('./frost-wasm/cosign_frost.js');

export interface DkgPlan {
  session: string;
  threshold: number;
  /** Every share index in the key, with the member key that will hold it. */
  holders: { idx: number; pk: string }[];
}

export interface DkgResult { groupX: string; shares: { idx: number; secret: string }[]; members: { idx: number; sharePub: string }[] }

export class DkgRun {
  plan: DkgPlan;
  done: DkgResult | null = null;
  private me: string;
  private mine: number[];
  private send: (toPk: string, msg: object) => void;
  private onDone: (r: DkgResult) => void;
  private secrets1 = new Map<number, string>();
  private packages1 = new Map<number, string>();   // everyone's part-1 packages, ours included
  private secrets2 = new Map<number, string>();
  private outgoing2 = new Map<string, [number, number, string][]>(); // holder pk → [from, to, package]
  private incoming2 = new Map<number, Map<number, string>>();        // our idx → from idx → package
  private timer: NodeJS.Timeout | undefined;

  constructor(plan: DkgPlan, me: string, send: (toPk: string, msg: object) => void, onDone: (r: DkgResult) => void) {
    this.plan = plan; this.me = me; this.send = send; this.onDone = onDone;
    this.mine = plan.holders.filter(h => h.pk === me).map(h => h.idx);
    const n = plan.holders.length;
    for (const idx of this.mine) {
      const r = JSON.parse(W.dkgPart1(idx, n, plan.threshold));
      this.secrets1.set(idx, r.secret);
      this.packages1.set(idx, r.package);
    }
  }

  private others() { return [...new Set(this.plan.holders.map(h => h.pk))].filter(pk => pk !== this.me); }
  private all() { return this.plan.holders.map(h => h.idx); }

  /** Send what we have, now and every 4 s until the run is done. */
  start() {
    const tick = () => {
      if (this.done) { clearInterval(this.timer); return; }
      const ours = this.mine.map(i => [i, this.packages1.get(i)!]);
      for (const pk of this.others()) {
        this.send(pk, { type: 'dkg1', session: this.plan.session, packages: ours });
        const r2 = this.outgoing2.get(pk);
        if (r2) this.send(pk, { type: 'dkg2', session: this.plan.session, packages: r2 });
      }
    };
    tick();
    this.timer = setInterval(tick, 4000);
  }

  stop() { clearInterval(this.timer); }

  /** A dkg1 or dkg2 message from another holder. */
  take(msg: any, fromPk: string) {
    if (msg.session !== this.plan.session || this.done) return;
    const theirs = new Set(this.plan.holders.filter(h => h.pk === fromPk).map(h => h.idx));
    if (msg.type === 'dkg1') {
      for (const [idx, p] of msg.packages ?? []) if (theirs.has(idx) && !this.packages1.has(idx)) this.packages1.set(idx, String(p));
      this.part2();
    } else if (msg.type === 'dkg2') {
      for (const [from, to, p] of msg.packages ?? []) {
        if (!theirs.has(from) || !this.mine.includes(to)) continue;
        if (!this.incoming2.has(to)) this.incoming2.set(to, new Map());
        this.incoming2.get(to)!.set(from, String(p));
      }
      this.part3();
    }
  }

  /** Once every part-1 package is in: part 2 for each of our shares. */
  private part2() {
    if (this.secrets2.size || this.packages1.size < this.all().length) return;
    for (const idx of this.mine) {
      const others = this.all().filter(i => i !== idx).map(i => [i, this.packages1.get(i)]);
      const r = JSON.parse(W.dkgPart2(this.secrets1.get(idx), JSON.stringify(others)));
      this.secrets2.set(idx, r.secret);
      for (const [to, p] of r.packages as [number, string][]) {
        const holder = this.plan.holders.find(h => h.idx === to)!.pk;
        if (holder === this.me) {
          if (!this.incoming2.has(to)) this.incoming2.set(to, new Map());
          this.incoming2.get(to)!.set(idx, p); // between our own shares: no relay needed
        } else {
          if (!this.outgoing2.has(holder)) this.outgoing2.set(holder, []);
          this.outgoing2.get(holder)!.push([idx, to, p]);
        }
      }
    }
    for (const [pk, r2] of this.outgoing2) this.send(pk, { type: 'dkg2', session: this.plan.session, packages: r2 });
    this.part3();
  }

  /** Once every part-2 package for our shares is in: our shares, and the key. */
  private part3() {
    if (this.done || !this.secrets2.size) return;
    const need = this.all().length - 1;
    if (!this.mine.every(i => (this.incoming2.get(i)?.size ?? 0) >= need)) return;
    const results = this.mine.map(idx => {
      const others = this.all().filter(i => i !== idx).map(i => [i, this.packages1.get(i)]);
      const r2 = [...this.incoming2.get(idx)!].map(([from, p]) => [from, p]);
      return { idx, ...JSON.parse(W.dkgPart3(idx, this.secrets2.get(idx), JSON.stringify(others), JSON.stringify(r2))) };
    });
    // Each of our shares must have computed the same key and the same share points.
    const key = results[0].groupX;
    if (results.some(r => r.groupX !== key || JSON.stringify(r.members) !== JSON.stringify(results[0].members))) throw new Error('our shares disagree about the key');
    this.done = { groupX: key, shares: results.map(r => ({ idx: r.idx, secret: r.share })), members: results[0].members };
    this.secrets1.clear(); this.secrets2.clear();
    // Keep sending part 2 a little longer: someone may still be waiting for ours.
    setTimeout(() => this.stop(), 20_000);
    this.onDone(this.done);
  }
}
