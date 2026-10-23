// What gets signed without asking, and what has to wait for the phone.
//
// Almost everything signs automatically. An event is held back only when it would
// noticeably destroy something, and that is judged by what it does, not by its kind:
// a follow list that adds one person is routine, one that drops most of them isn't.
// That judgement needs the version it replaces, which is what the archive keeps.

export interface Ev { kind: number; content: string; tags: string[][]; created_at: number; pubkey?: string; id?: string; sig?: string }

/** Kinds whose latest version the servers keep, so they can compare and restore. */
export const ARCHIVED = new Set([
  0,      // profile
  3,      // follows
  10000,  // mutes
  10001,  // pins
  10002,  // relays
  10003,  // bookmarks
  10004,  // communities
  10006, 10007, // blocked / search relays
  10015,  // interests
  10030,  // emoji list
  30000, 30001, 30002, 30003, 30004, 30015, 30030, // sets
]);

const NAMES: Record<number, [string, string]> = {
  0: ['profile', 'profile field'], 3: ['follow list', 'follow'], 10000: ['mute list', 'mute'], 10001: ['pinned notes', 'pin'],
  10002: ['relay list', 'relay'], 10003: ['bookmarks', 'bookmark'], 10004: ['communities', 'community'],
  10006: ['blocked relays', 'relay'], 10007: ['search relays', 'relay'], 10015: ['interests', 'interest'], 10030: ['emoji list', 'emoji'],
  30000: ['follow set', 'person'], 30001: ['list', 'item'], 30002: ['relay set', 'relay'], 30003: ['bookmark set', 'bookmark'],
  30004: ['curation set', 'item'], 30015: ['interest set', 'interest'], 30030: ['emoji set', 'emoji'],
};
const EVENT_NAMES: Record<number, string> = {
  1: 'note', 4: 'DM', 5: 'deletion', 6: 'repost', 7: 'reaction', 13: 'DM', 14: 'DM', 16: 'repost', 62: 'request to vanish',
  1111: 'comment', 9734: 'zap request', 22242: 'relay login', 24242: 'upload login', 27235: 'web login', 30023: 'article', 30078: 'app data',
};

export const kindName = (k: number) => NAMES[k]?.[0] ?? EVENT_NAMES[k] ?? `kind ${k} event`;
const plural = (n: number, k: number) => `${n} ${NAMES[k]?.[1] ?? 'item'}${n === 1 ? '' : 's'}`;

export const dTag = (e: Ev) => e.tags.find(t => t[0] === 'd')?.[1] ?? '';
/** Replaceable events are keyed by kind; parameterised ones by kind and d tag. */
export const keyOf = (e: Ev) => (e.kind >= 30000 && e.kind < 40000 ? `${e.kind}:${dTag(e)}` : `${e.kind}`);

function items(e: Ev): string[] {
  switch (e.kind) {
    case 3: return e.tags.filter(t => t[0] === 'p').map(t => t[1]);
    case 10002: case 10006: case 10007: case 30002:
      return e.tags.filter(t => t[0] === 'r' || t[0] === 'relay').map(t => t[1].replace(/\/+$/, ''));
    default: return e.tags.filter(t => t[0] !== 'd' && t[0] !== 'title' && t[0] !== 'description').map(t => JSON.stringify(t.slice(0, 2)));
  }
}

const PROFILE_FIELDS = ['name', 'display_name', 'picture', 'about', 'nip05', 'lud16', 'banner', 'website'];
const profile = (e?: Ev): Record<string, unknown> => { try { return JSON.parse(e?.content ?? '{}') ?? {}; } catch { return {}; } };
const filled = (v: unknown) => typeof v === 'string' ? v.trim().length > 0 : v != null;

export interface Assessment {
  /** Set when the phone has to approve: what would be destroyed, in plain words. */
  hold?: string;
  /** For archived kinds: what changed, for the history the phone shows (and can undo). */
  change?: string;
}

/** Judge an event against the version it replaces. */
export function assess(e: Ev, prev?: Ev): Assessment {
  if (e.kind === 62) return { hold: 'Ask relays to erase everything you have ever published' };

  if (e.kind === 5) {
    const targets = e.tags.filter(t => t[0] === 'e' || t[0] === 'a');
    const core = e.tags.filter(t => t[0] === 'a' || t[0] === 'k').map(t => Number(t[1].split(':')[0])).filter(k => ARCHIVED.has(k));
    if (core.length) return { hold: `Delete your ${kindName(core[0])}` };
    if (targets.length >= 5) return { hold: `Delete ${targets.length} of your events` };
    return {};
  }

  if (!ARCHIVED.has(e.kind)) return {};

  if (e.kind === 0) {
    const was = profile(prev), now = profile(e);
    const wiped = PROFILE_FIELDS.filter(f => filled(was[f]) && !filled(now[f]));
    const changed = PROFILE_FIELDS.filter(f => filled(now[f]) && now[f] !== was[f]);
    if (prev && (wiped.length >= 2 || (Object.keys(now).length === 0 && Object.keys(was).length > 0)))
      return { hold: `Wipe your profile: ${wiped.join(', ') || 'everything'}` };
    const parts = [...changed.map(f => `${f.replace('_', ' ')} changed`), ...wiped.map(f => `${f.replace('_', ' ')} removed`)];
    return { change: prev ? `Profile: ${parts.join(', ') || 'no visible change'}` : 'Profile set' };
  }

  const before = prev ? items(prev) : [];
  const after = items(e);
  const kept = new Set(after);
  const removed = before.filter(x => !kept.has(x)).length;
  const added = after.filter(x => !new Set(before).has(x)).length;
  const name = kindName(e.kind);

  if (prev) {
    if (after.length === 0 && before.length >= 3) return { hold: `Empty your ${name} (it has ${plural(before.length, e.kind)})` };
    const relayish = [10002, 10006, 10007, 30002].includes(e.kind);
    const big = relayish ? removed >= 2 && removed >= before.length * 0.5 : removed >= 10 && removed >= before.length * 0.2;
    if (big) return { hold: `Remove ${removed} of your ${before.length} ${NAMES[e.kind]?.[1] ?? 'item'}s` + (added ? ` (and add ${added})` : '') };
  }

  const bits = [added && `+${plural(added, e.kind)}`, removed && `−${plural(removed, e.kind)}`].filter(Boolean);
  return { change: `${name[0].toUpperCase()}${name.slice(1)}: ${bits.join(', ') || (prev ? 'reordered' : `${after.length} ${NAMES[e.kind]?.[1] ?? 'item'}s`)}` };
}
