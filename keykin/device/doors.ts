// What a site may ask of the account, whatever door it comes through (Doors §2, core §6.7.5, §5.7
// item 5): never the account's machinery. Checked on the device before any signing round, so a site's
// event never reaches a co-signer as one of these (review 11 H1). Scopes (Doors §1, device/grants.ts)
// narrow it further, decrypts to the account's own key included.

import { KeykinError } from '../src/bytes.ts';
import { signpostD } from '../src/codes.ts';
import { FAMILY_KINDS } from '../src/families.ts';
import { KIND_EPOCH, KIND_CHANGE, KIND_SIGNPOST } from '../src/types.ts';

/** Doors 20 §2: the vaults spec's machinery (AUTH, CERT, KEYRING) and invitations; provisional numbers, as core's. */
export const VAULT_KINDS = new Set([4810, 4811, 30811]);
export const KIND_VAULT_INVITE = 4812;
const VAULT_SECRETS = ['keys', 'keys_ref', 'secret', 'inboxes', 'genesis'];
const parse = (t: string): unknown => { try { return JSON.parse(t); } catch { return null; } };
const vaultShape = (x: unknown) => !!x && typeof x === 'object' && !Array.isArray(x) && 'vault' in (x as object) && VAULT_SECRETS.some((k) => k in (x as object));
/** Whether a plaintext is vault material no site may get, or have encrypted (Doors 20 §2): a kind-4812 rumor, or an
 *  object with `vault` and `keys`, `keys_ref`, `secret`, `inboxes` or `genesis`, at the top level or in a rumor's
 *  content. */
export function vaultPlaintext(text: unknown): boolean {
  if (typeof text !== 'string') return false;
  const x = parse(text) as any;
  if (vaultShape(x)) return true;
  if (x && typeof x === 'object' && !Array.isArray(x) && Number.isInteger(x.kind) && typeof x.content === 'string') {
    if (x.kind === KIND_VAULT_INVITE) return true;
    if (vaultShape(parse(x.content))) return true;
  }
  return false;
}

const no = (why: string): never => { throw new KeykinError('declined', why); };

/** Refuse a site's event that touches the account's machinery. `g` the account, `backupKeys` every
 *  backup key it has had (signpost names come from them). */
export function siteGuard(e: { kind: number; tags: string[][] }, g: string, backupKeys: string[], protectedIds: Set<string> = new Set(), kindOf?: (id: string) => number | undefined) {
  if (e.kind === KIND_EPOCH || e.kind === KIND_CHANGE) no('account machinery');
  // Doors 20 §2: vault machinery is the vault apps' own, through the device API, never a site's.
  if (VAULT_KINDS.has(e.kind)) no('vault machinery is never a site\'s to sign');
  if (e.kind === 5) for (const t of e.tags) {
    if (!Array.isArray(t) || typeof t[1] !== 'string') continue;
    if (t[0] === 'k' && VAULT_KINDS.has(Number(t[1]))) no('a deletion of vault machinery');
    if (t[0] === 'a' && VAULT_KINDS.has(Number(t[1].split(':')[0]))) no('a deletion of vault machinery');
    if (t[0] === 'e' && VAULT_KINDS.has(kindOf?.(t[1].toLowerCase()) ?? -1)) no('a deletion of vault machinery');
  }
  if (FAMILY_KINDS.has(e.kind)) no('a key-family event is the person\'s own act, never a site\'s');
  const signposts = new Set(backupKeys.map(signpostD));
  const reserved = (d: string) => signposts.has(d.toLowerCase()) || d.startsWith('keykin-');
  const d = e.tags.find((t) => t[0] === 'd')?.[1] ?? '';
  if (e.kind === KIND_SIGNPOST && reserved(d)) no('the account\'s signpost and keykin- data are never a site\'s to write');
  if (e.kind === 5) for (const t of e.tags) {
    const v = (t[1] ?? '').toLowerCase();
    if (t[0] === 'a' && (([...signposts].some((s) => v.includes(s)) && v.includes(g)) || v.includes(':keykin-'))) no('a deletion of the account\'s signpost or keykin- data');
    // Nor by event id: the grant events this device knows (their ended lists keep signed-out sites out, review 16 M3).
    if (t[0] === 'e' && protectedIds.has(v)) no('a deletion of the account\'s keykin- data');
  }
}
