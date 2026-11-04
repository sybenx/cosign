// What a site may ask of the account, whatever door it comes through (Doors §2, core §6.7.5, §5.7
// item 5): never the account's machinery. Checked on the device before any signing round, so a site's
// event never reaches a co-signer as one of these (review 11 H1). Scopes (Doors §1) narrow this further
// once they exist; until then a site also gets no decryption of what the account wrote to itself
// (review 11 H2).

import { KeykinError } from '../src/bytes.ts';
import { signpostD } from '../src/codes.ts';
import { FAMILY_KINDS } from '../src/families.ts';
import { KIND_EPOCH, KIND_CHANGE, KIND_SIGNPOST } from '../src/types.ts';

const no = (why: string): never => { throw new KeykinError('declined', why); };

/** Refuse a site's event that touches the account's machinery. `g` the account, `backupKeys` every
 *  backup key it has had (signpost names come from them). */
export function siteGuard(e: { kind: number; tags: string[][] }, g: string, backupKeys: string[]) {
  if (e.kind === KIND_EPOCH || e.kind === KIND_CHANGE) no('account machinery');
  if (FAMILY_KINDS.has(e.kind)) no('a key-family event is the person\'s own act, never a site\'s');
  const signposts = new Set(backupKeys.map(signpostD));
  const reserved = (d: string) => signposts.has(d.toLowerCase()) || d.startsWith('keykin-');
  const d = e.tags.find((t) => t[0] === 'd')?.[1] ?? '';
  if (e.kind === KIND_SIGNPOST && reserved(d)) no('the account\'s signpost and keykin- data are never a site\'s to write');
  if (e.kind === 5) for (const t of e.tags) {
    const v = (t[1] ?? '').toLowerCase();
    if (t[0] === 'a' && (([...signposts].some((s) => v.includes(s)) && v.includes(g)) || v.includes(':keykin-'))) no('a deletion of the account\'s signpost or keykin- data');
  }
}

/** Until Doors scopes exist: no site decrypts what the account encrypted to itself. */
export function siteMayDecrypt(peer: string, g: string) { if (peer.toLowerCase() === g) no('the account\'s own data is not a site\'s to read'); }
