// The time, as the network tells it, not as this machine's clock says. A clock set
// ahead (by mistake or on purpose) would otherwise let something dated in the future
// look like now. The Date header of a few well-known HTTPS sites can't be forged
// without breaking TLS; the median of them sets the offset from the local clock.

const SOURCES = ['https://cloudflare.com', 'https://www.google.com', 'https://cosign.aaro.cc', 'https://github.com'];
let offset = 0;          // seconds to add to the local clock
let checkedAt = 0;       // when the network last agreed on a time (local ms)

export const trustedNow = () => Math.floor(Date.now() / 1000) + offset;
/** How far this machine's clock is from the network's, in seconds (positive = ahead). */
export const skew = () => -offset;
export const verified = () => Date.now() - checkedAt < 6 * 3600_000;

export async function checkClock(log: (t: string) => void = () => {}) {
  const read = async (url: string) => {
    const t0 = Date.now();
    const r = await fetch(url, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(5000) });
    const d = Date.parse(r.headers.get('date') ?? '');
    if (Number.isNaN(d)) throw new Error('no date');
    return d / 1000 - (t0 + Date.now()) / 2000; // their time minus ours, at the midpoint of the request
  };
  const got = (await Promise.allSettled(SOURCES.map(read))).flatMap(r => (r.status === 'fulfilled' ? [r.value] : []));
  if (got.length < 2) return; // not enough to trust: keep what we had
  got.sort((a, b) => a - b);
  const median = got[Math.floor(got.length / 2)];
  // Two sources that disagree by minutes are no answer at all.
  if (got[got.length - 1] - got[0] > 120) return log(`clock check: sources disagree, keeping the last answer`);
  offset = Math.round(median);
  checkedAt = Date.now();
  if (Math.abs(offset) > 60) log(`this machine's clock is ${Math.abs(offset)} s ${offset < 0 ? 'ahead' : 'behind'}: using the network's time`);
}
