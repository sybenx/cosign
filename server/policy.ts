// Who has to agree to what.
//
// The rule is the same on every member: an "auto" kind can be signed by any two
// members, so the two servers sign it between them and the phone never hears
// about it. Every other kind needs the phone in the pair, and the phone asks its
// user. A server will not co-sign a sensitive event with the other server, so
// two servers, or one compromised server and the other, cannot sign one alone.

export const DEFAULT_AUTO_KINDS = [
  1,     // note
  6, 16, // reposts
  7,     // reaction
  1111,  // comment
  9734,  // zap request
  22242, // relay auth (NIP-42)
  24242, // blossom auth
  27235, // HTTP auth (NIP-98)
  30078, // app settings
];

export const KIND_NAMES: Record<number, string> = {
  0: 'profile', 1: 'note', 3: 'follow list', 4: 'DM (old style)', 5: 'deletion', 6: 'repost', 7: 'reaction',
  13: 'DM seal', 14: 'DM', 16: 'repost', 1059: 'gift wrap', 1111: 'comment', 9734: 'zap request',
  10000: 'mute list', 10002: 'relay list', 22242: 'relay login', 24242: 'file upload auth', 27235: 'web login',
  30023: 'article', 30078: 'app settings',
};

export const kindName = (k: number) => KIND_NAMES[k] ?? `kind ${k}`;

export interface Member { idx: number; name: string; role: 'server' | 'phone'; pk: string | null; sharePub: string }

/** May this signer take part in signing `kind` with exactly these participants? */
export function allows(kind: number, participants: number[], members: Member[], autoKinds: number[]): { ok: boolean; why: string } {
  if (autoKinds.includes(kind)) return { ok: true, why: 'auto' };
  const phone = members.find(m => m.role === 'phone');
  if (phone && participants.includes(phone.idx)) return { ok: true, why: 'phone in the pair' };
  return { ok: false, why: `${kindName(kind)} needs the phone` };
}
