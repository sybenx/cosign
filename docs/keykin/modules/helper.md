# Keykin module: Helper

Draft 4 · 2026-11-03 · module of [Keykin Core](../core.md) draft 14.2 · not built

A **helper** is a family member's or friend's always-on box that holds the helper seat (3 shares, core
§3.1, I6). With one server it can post for the account while every one of the person's devices sleeps.
It exists only if the person opts in. This module says what it is for, how it is added, stopped and
removed, what it may sign, and what its owner can see. The core wins any disagreement, and nothing here
may weaken it.

The bar is the core's: an nsec in a password manager. A helper is like giving a trusted friend a key that
can only post, never change the account, and can be taken back with one tap. It is only worth having if
the person wants some sites answered while their phone is off.

## 1. What a helper is for

One job: **answering chosen sites while devices sleep.** Bots, cross-posters, schedulers and other
post-only clients connect to the helper instead of to a phone, and the helper signs for them with one
server.

What the core lets a helper do, and nothing more (core §5.7 item 8):

- coordinate a round with one server only for kinds 1 (notes and replies), 1111 (comments), 7
  (reactions), 6 and 16 (reposts), 9734 (zap requests), 20, 21 and 22 (media posts) and 22242 (relay
  auth). Servers refuse anything else, so even a stolen helper box can't change the profile, lists,
  relays or wallet, delete anything, or log in to other services;
- never co-sign for anyone, approve an account change, or cancel a wait (core §2, §6.2, §6.3); and no
  device co-signs its rounds, so every helper round has a server in it;
- never get decryption answers, the data key or release seeds, so it can't read or write messages,
  private lists or wallets. (Relay auth lets it sign in to relays as the person, which can show it a
  private relay group's posts and who writes to the person, though not message contents.)
- never send `hold`, `cancel`, `push_register`, `notify_register`, `need_seeds`, `take_out` or `ecdh`;
  servers refuse them from a helper.

**Scheduled posts** need no helper: a device signs a future-dated note with the person present (core
§5.7 item 4 allows it for these kinds) and hands the signed event to any always-on publisher, the helper
included, to publish at its time. Whoever holds it can read it before then, and a stop doesn't stop it
being published, because it is already signed; **Unschedule** asks the publisher to drop it.

## 2. Sites the helper answers

- **A site is either the phone's or the helper's.** On the connect screen the person may pick "Let
  *helper* answer for this site". The device then asks the helper to mint a `bunker://` link (Doors and
  grants §3.3), or, for a `nostrconnect://` code the device scanned, passes the code to the helper, which
  connects. Either way the helper is the grant's **home**: it holds the signer key and answers, and no
  device does. The connect questions are asked on the device.
- **Every helper grant is also an entry in the grant list of the device that asked for it** (Doors and
  grants §2, `by` = that device, marked `helper`). So removing that device ends it, by the core's rule
  that a removed device's grants are revoked, and the tombstone is delivered to the helper. A grant in a
  helper report that no current device's list names gets the warning of §4.
- A helper grant has only the kinds of §1. It never widens: for more, the person connects the site to a
  phone instead, which is a new grant.
- Requests outside those kinds get `declined: ask on your phone`. Encrypt and decrypt requests get
  `unsupported:`, since the helper can't do them.
- **Signing out reaches the helper.** The helper reports its grants to devices (§4), and every device
  lists them. A sign-out, End, expiry or `logout` is a tombstone delivered to the helper (Doors and grants
  §2), which ends the grant and answers `revoked:` for 30 days. The helper fetches its inbox at least
  every 5 minutes (Doors and grants §2).

## 3. Adding, stopping and removing

### 3.1 Adding

1. The friend installs a Keykin app on an always-on machine (a desktop app left running, or a home-server
   package) and picks **Be a helper**. It shows a join code (core §4.1) carrying its host key, and tells
   the friend: "Your npub will be listed in *name*'s account." Once its welcome names the account, it
   checks the machine and leaves at once if a Keykin member of that account is on it. Afterwards any
   Keykin app **or browser extension** on that machine (extensions ask the helper app over native
   messaging) refuses to join this account as a device.
2. On a device, the person picks **Add a helper**. The opt-in screen says, once and plainly: "*Name*'s
   box will be able to post notes, replies, reactions, reposts and media as you, together with one of your
   servers, for the sites you choose. It can't change your profile, lists or wallet, read your messages or
   delete anything, unless it and one of your servers work against you together: then they hold your whole
   key. It can sign in to your relays as you, which can show it posts in private relay groups and who
   writes to you. Any of your devices can stop it at once."
3. The typed join check (core §4.1), then the approval (a lock, a second device, or the paper), then
   `[seat helper→H, redeal]`. The device and one server repair the helper seat (core §6.7.6 F6).

The helper's member entry is `{"key", "kind": "helper", "shares": <the helper seat>, "host": <its host
key>, "operator": <the friend's npub>}`. No host holds both the helper seat and a server seat (core I6).
The device also compares the helper's operator with every server's, when adding the helper and when
adding a server, and refuses a match; replacement picks skip the helper's operator. There is at most one helper (core I5).

### 3.2 Stopping, at once

**Stop helper** is on every device, with no approval (core §5.7, `helper_stop {key}`): every server
refuses that helper key's rounds from then on, the stop travels to servers seated later, and every device
is told. It only takes power away, so a lone device with no lock can do it too. A stopped helper stays in
its seat until it is removed or replaced, or until **Resume helper** (`helper_resume {key}`) with an
approval (a lock, two devices, or the paper).

### 3.3 Removing or moving

- **Remove the helper**: `[seat helper→null, redeal]` with an approval (core F6). It also clears the stop.
- **Moving to another box** is a seat change to the new box's member key, with the same approval.
- Either way every grant the helper was home to ends, and the screen says so: "*3* sites will ask you to
  sign in again."
- A helper that is offline needs nothing: no seat depends on it.
- A helper that has been unreachable for 30 days is shown once, calmly: "*Name*'s helper has been off for a
  month." The person may stop or remove it; nothing is done for them.

## 4. What devices see

- **Reports.** The helper keeps **one cumulative report per device**, `helper_report {event ids, grants,
  last_used, logouts}`, at most 64 KB, sealed, as a delivery that replaces its earlier one, updated once an
  hour or every 50 events. When it is full, the oldest event ids give way to a count and a time span
  (`dropped {count, from, to}`). A device fetches the events by id from relays, checks each (`pubkey == g`, the
  signature) and writes Device policy's metadata for them (Device policy §1), marking the attribution as
  the helper's. Devices show it quietly: "*Helper* signed 12 notes for *Bot*."
- **Signing nobody reported.** A device that fetches account events no device's metadata and no helper
  report accounts for, after two hours' grace, shows one quiet line: "Posts you didn't make from any device
  appeared." It offers **Stop helper** (§3.2) when those events are of the helper's kinds, and **Report a
  device lost** in any case, since a stolen phone can post too. Events of the helper's kinds inside a
  report's `dropped` span show as "*Helper* signed many posts while your devices were off" instead. On an
  imported account it adds: "Your old key may still be in use somewhere." 
- After an heir takes over (Backup module §4), the app offers to remove the helper. Helper rounds never
  count as a sign of life for an heir wait.

## 5. What the friend can see

The friend runs the box, so they can see what it holds:

- the account's membership (its devices, servers, helper and backup key), from its welcome;
- the events it signs, and the requests of the sites it answers;
- the backup material, wrapped under release seeds it never gets.

They can't read messages, private lists or wallet content. The opt-in screen links to this list.

## 6. Messages

| `type` | From → to | `cls` |
|---|---|---|
| `helper_mint {site}` / `helper_link {bunker}` | device → helper / back | `ask` |
| `helper_report {event ids, grants, last_used, logouts}` | helper → devices (delivery, replacing) | `member` |
| `helper_connect {nostrconnect}` | device → helper | `ask` |

## 7. Limits, said plainly

- **The helper plus one server** can post notes, replies, reactions, reposts and media as the person,
  silently, until any device stops it (core §10). A dishonest friend or a stolen box can post spam or
  worse in the person's name.
- **The helper plus one dishonest server is the whole key** (3 + 1 = 4 points, core §10), offline and with
  no kind limit. That is why the helper's operator may never run one of the servers.
- **The helper alone signs nothing**, and the helper plus the paper is worth nothing without a server's
  wait (core §7.2, I5).
- **A dishonest helper at a redeal** learns `δ`, and with a retired server is the key (core §10).
- **The friend's box can be stolen.** Its shares are stored as core §7.3 says, but the friend's machine
  is not the person's.
- **Removing or moving a helper** needs the paper on a lone device with no lock; stopping it never does.

## Changes

- **Draft 4**, from its third red team (0 critical, 1 high):
  - every helper grant is in the asking device's grant list, so removing that device ends it, and
    unclaimed grants are flagged (H1).

  The mediums and lows:
  - a stopped helper still gets redeals; only removal cuts it off (M1, stated in core 14.2);
  - stop and resume ordered by a counter (M2, core 14.2);
  - picks skip the helper's stated operator; the check is only as good as that statement (M3);
  - full reports keep a count and span, with no false warning (M4);
  - helper relay sign-in only to the account's own relays (M5, core 14.2);
  - extensions on the helper's machine refuse to join too (M6);
  - relay sign-in on the opt-in screen, scheduled posts readable and not stopped, the machine check after
    the welcome, the old key on imported accounts (lows).
- **Draft 3**, from its second red team (0 critical, 2 high):
  - the stop travels to new servers and is fetched before helper rounds (H1, core 14);
  - the helper's operator never runs a server, and the helper plus one dishonest server is said plainly
    (H2, core 14).

  The mediums and lows:
  - the stop names the helper key; **Resume helper** with an approval (M1, M7, core 14);
  - devices never co-sign helper rounds (M2, core 14);
  - one capped, replacing report per device, with event ids (M3);
  - unreported posts offer both Stop and Report lost, after two hours (M4);
  - the helper fetches its inbox every 5 minutes (M5);
  - what relay auth shows (M6);
  - `nostrconnect://` through the device (M8);
  - no device joins on the helper's machine (M9);
  - seams and messages (lows).
- **Draft 2**, from its first red team (1 critical, 6 high) and the user's answers:
  - servers co-sign helper rounds only for posting kinds (C1, core 14);
  - sites are the helper's or the phone's, with sign-outs delivered to it (H1, H6, M5, M7);
  - helper grants never widen (H2, M6);
  - **Stop helper** on any device, no approval (H3, core 14);
  - no helper co-signing for devices (H4, core 14);
  - a host field, and no host with both the helper and a server seat (H5, core 14);
  - scheduled posts are pre-signed notes (M1, M2);
  - batched reports that feed Device policy's metadata (M3, L3);
  - unreported signing noticed (M4);
  - sites reconnect on remove or move, heirs, messages refused from a helper, the friend told about
    the npub, a message table (L1, L2, L5, L6, L7).
- Draft 1.
