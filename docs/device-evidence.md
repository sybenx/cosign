# When one of your devices may believe in another — proposal, first draft

**Status: proposal, for review. Nothing here is built.** It exists because the same hole was
found three times this week, in three unrelated pieces of work, by three different reviewers. It
is one hole.

> **A device takes its member list wholesale from whatever a server sends.** `onMembers`
> (`Phone.kt:1455-1462`) accepts the list if it contains this phone and its epoch is not older,
> and nothing else. The extension is better and still not safe: it keeps the share points it
> already knows but takes the **member set** from the list (`device.ts:213-226`). So
> *"every device of yours"* means *"every device, plus anything a server wrote in"*, and live
> finding #1 — only partly fixed in 0.12.6 — is precisely a server writing one in.

Where it has already bitten:

- **Per-site mailbox keys** (`claude/per-site-signer-keys`, 9091914). `changed()` seals every
  connected site's mailbox key to every member with role `device` or `phone`
  (`Phone.kt:1996-1999`), and the receiver adopts a `site_key` from anyone on that list
  (`:2056`). One dishonest server adds a fake device and collects **every site's mailbox**, which
  is the signer for each of them. That branch is on hold for this.
- **The app-key namespace salt** (`docs/app-keys.md` §4.4.1). "Deal `S` to every member device"
  meant dealing it to whoever a server listed. Already written up there as a MUST, pointing here.
- **The DM spec's per-site keys** (`~/igloo/cosign-dm-spec.md`). Its own red team hit the same
  wall and avoided it by **not copying at all** — each site's mailbox key stays on the device
  that connected the site.

## 1. The rule

> **A device MUST NOT seal a secret to, or accept a secret from, a member it knows only because a
> server said so.** It may do either only with a member it has **evidence** of, in the sense of
> §2 — evidence this device gathered itself, which a member with no shares cannot manufacture.

This is the device-side twin of `mayAct` on the server (`group.ts:101`), which already refuses
the six irreversible actions to a member it has only ever heard about from another server's list,
and clears that mark when the member proves it holds the shares the list claims. The rule here
is the same idea applied to secrets instead of actions, and the reason it is needed separately is
that a server's gate cannot help: the secret never passes through a server.

## 2. What counts as evidence

Three kinds, in the order a device is likely to get them.

**(a) This device vouched for it.** The person scanned the newcomer's code on this device and
unlocked it, and this device dealt part of the newcomer's share. Nothing a server says is
involved. The record already exists — `vouch(pk)` / `vouchedFor(pk)` (`Phone.kt:1398-1410`) — but
**it expires** after `VOUCH_LIFE`, because it was written to survive the signer process being
killed mid-add, not to be remembered. Using it as evidence means keeping it, which is §5's first
open question.

**(b) A verified partial from that member's indices.** The strongest and the cheapest: a member
with no shares can never produce a partial signature that verifies against the share points, nor
(since 0.12.7) a decryption partial with a proof. So:

> **A device MAY treat a member as proven when it has verified that member's partial — a
> signature partial against `verifyPartial`, or an ECDH partial against its proof — for the
> indices the member list claims, in the current epoch.** It MUST record which indices were
> proven, not merely the member's key.

This is self-bootstrapping and needs no new message: it happens the first time two devices sign
or read together. `signForApp` already calls `FrostNative.verifyPartial` on every partial it
receives (`Phone.kt:1726`) and throws the result away; keeping it is the whole change.

**(c) A vouch passed on, signed.** Device A vouched for B; later B vouches for C; A has never
met C. For A to believe in C, B must say so in a way A can check:

> **A device MAY accept a member as proven on a `vouch` record signed by the enrollment key of a
> member it already has evidence of, naming the new member's key and indices and the epoch it was
> added in.** A record MUST NOT be accepted from a member whose own standing rests on a record
> signed by the member it is vouching for, and a chain MUST be at most two long.

This is the only one that is new machinery, and it is the only one that solves "three devices and
the one that did the vouching is in a drawer". §4 says why it should wait.

**What is explicitly not evidence:** a member appearing in a `members` message; a member a server
describes as a device; a member that has answered a ping; a member with a plausible name. The
first is the hole, and the other three are what an implementer reaches for next.

## 3. What a device does with no evidence

> **It does not send, and it does not fail.** A secret that cannot be sealed to a member yet is
> **held, not dropped**: the device keeps it and seals it the moment evidence arrives, which for
> (b) is the first round the two take part in together. Nothing is shown to the person, because
> nothing is wrong.

> **A device MUST NOT ask a server to carry a secret to a member it cannot verify**, and MUST NOT
> fall back to a weaker check when a server says the member is real.

## 4. The interim, which is also the recommendation

For per-site mailbox keys, **do not copy them at all.** The site's mailbox key stays on the device
that connected the site; only that device answers for that site.

This is not a stopgap: it is what the site-facing DM spec already specifies after its own red
team, and it has three things going for it over any evidence scheme. It needs no new trust
machinery. It cannot be got wrong by a mistake in the evidence rule. And the thing it costs —
a second device cannot answer a site the first one connected — is **visible to the person**, who
sees the site is signed in on their phone and not on their laptop, which is the right way for a
limitation to be felt.

> **`claude/per-site-signer-keys` MUST drop `changed()`'s copying loop and the `site_key`
> receiver before it ships.** Not gate them: remove them. A receiver that exists is a receiver
> someone will loosen.

The salt in `app-keys.md` §4.4.1 cannot take this route — a namespace is useless on one device —
so it needs (a) or (b), and it is blocked behind them. That is the honest reason the app-key work
has a device-evidence dependency and this document is where it lives.

## 5. Still open

1. **Whether a vouch record is kept for ever.** Making `vouching` durable turns a short-lived
   note into a permanent list of every device this one ever helped add. That is a small privacy
   cost on a device that is already holding the account's shares, and I think it is worth it —
   but it should be a decision rather than a side effect of deleting one expiry check.
2. **What proof survives a refresh.** Evidence (b) is about indices in an epoch, and a refresh
   moves the indices' points. A member proven in epoch 7 is presumably still the same device in
   epoch 8 — but the thing that was verified is gone. Either evidence carries forward by the
   member's key (weaker, and a key is what a server writes) or it is re-earned each epoch
   (stricter, and a quiet device goes unproven for a long time). Mine, and I lean towards
   carrying it forward while recording the epoch it was earned in.
3. **Whether (c) is worth building at all**, given (b) arrives free on first joint use. The case
   it answers is a third device added by a phone that is then lost before the laptop and the
   third device ever sign together. That is real but rare, and the alternative — the person
   vouches again on the laptop — is a thing they can do.
4. **The extension and the Mac have no vouching path at all.** The extension cannot add a device
   (no `remove_member`, no vouch UI), so on a browser member only (b) is available, and that is
   worth confirming rather than assuming.
