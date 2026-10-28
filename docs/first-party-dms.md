# A member device's own app reading and sending DMs — proposal, first draft

**Status: proposal, for review. Nothing here is built.** Written as specification text so it can
be attacked. The site-facing half is settled in `~/igloo/cosign-dm-spec.md` (code-connected
sites, per-site keys, the grant, migration, push) and the rule both halves obey is
`~/igloo/cosign-decrypt-rule.md` (**R1–R8**). Neither is restated here; where this document needs
more it adds to them, and it may not contradict them.

## 1. What this is about, and the thing I had wrong

**Corrected in draft 2, after a joint red team over this and the site-facing half
(`~/igloo/cosign-dm-joint-redteam.md`: four hard contradictions and one wrong premise — the wrong
premise was mine).**

Draft 1 said Marble embeds the library, therefore *is* the signer, therefore the capability is
already shipped and only the policy is missing. **That is false, and the code is better than I
described it.** Verified myself rather than taken on trust:

- **The library runs key material in a second process.** `Proc.kt` says it in as many words: the
  signer process (`:signer`) holds the shares, and the main process "draws everything else,
  including what strangers post (pictures, videos, translations), and only ever asks the signer
  through `ISigner`; it never sees a share." `Signers`, `Secrets` and `SignerService` each call
  `Proc.signerOnly(...)` and **throw** outside it (`Signers.kt:25`, `Secrets.kt:24`,
  `SignerService.kt:38`), and `Cosign.init` only constructs `signers` when `Proc.isSigner`
  (`Cosign.kt:36-45`). Eight components carry `android:process=":signer"`.
- **The interface deliberately omits the peer.** `ISigner.aidl` exposes `nip44Own(slot, text,
  encrypt)` and its comment is the design: *"The other side is always this account's own key: no
  peer goes in, so this can never read anyone else's messages."* Nothing on that interface takes
  a peer.

So `Phone.nip44` is public **within the signer process** and unreachable from the process that
renders other people's media. The line is not drawn by convention, as draft 1 claimed — it is
enforced by a process boundary, an AIDL surface and three runtime checks.

**What that changes, and all of it is in this proposal's favour except the cost:**

1. **The capability is not shipped.** Building this means putting a peer-taking call on
   `ISigner`, which is the real cost draft 1 priced at zero, and which punches a hole in exactly
   the boundary `nip44Own` exists to hold.
2. **There is a better way in, and it is already built.** Marble's Messages pane can ask its own
   signer through the **NIP-55 door** rather than through a new IPC method. That door already has
   the question, the recorded answer, a grant the person can remove, and UI that runs in the
   signer process (`Nip55Provider`, `Nip55Request`). It is the same door another app would use,
   which means the capability arrives with its own revocation instead of needing one invented.
   **This proposal takes that route**, and §11.1's open question answers itself: the line is
   already enforced, in the right place, and should stay there.
3. **Draft 1's §3 and §9.1 were too pessimistic** and were licensing a weaker design than the
   code supports. "A compromised host holds the shares" is false for the realistic compromise:
   the process that parses a stranger's video holds nothing. §3 and §9 are rewritten accordingly.

> **A new peer-taking method MUST NOT be added to `ISigner`.** A first-party pane that wants to
> read or send messages goes through the signer's own NIP-55 door, with the question, the record
> and the removable grant that door already carries.

## 2. What it must deliver

- Marble's Messages pane reads and sends NIP-17 DMs as the account.
- Marble reads and writes the account's own private data — mutes, bookmarks, private list items
  — which is `decrypt-to-self` and a separate permission under R4.
- Neither is available to a site or to another app through this document; those go through the
  site-facing half and its grant.

## 3. The permission, and whether the person is asked

R2 leaves this to this document. The answer is **yes, asked once, per capability, and recorded
the same way a site's answer is** — and the reasoning matters more than the answer.

> **A host app of the library MUST NOT decrypt with a peer other than the account's own key, or
> encrypt to one, until the person has answered the `messages` question on that device; and MUST
> NOT decrypt to self until they have answered `private data`.** The answers are recorded as R6
> requires, against the library's own grant, and are visible and switchable in the same list as
> every site's.

Three reasons, none of which is "to be safe":

- **There is nothing else to revoke.** A site's access ends when its grant is removed. The
  library's own grant is remade whenever the host asks (`connectApp(own, appName)`), so removing
  it achieves nothing — the next call recreates it. Without a recorded answer the only revocation
  is removing the device from the account, which is `app-keys.md` §11.11's complaint and is far
  too big a hammer for "stop Marble reading my DMs".
- **The person cannot tell the two apart, and should not have to.** Marble is one app with a
  Messages pane and a notes pane. "Marble may read your messages" is a sentence about the app,
  and the user's mental model is the app, not the process boundary. An account where a site must
  ask and the app need not is a model nobody can hold.
- **It costs one sheet, once.** This is not a per-message prompt and not a per-contact prompt
  (R1 — and for reading, per-contact is impossible; see §5).

> **The words MUST be the words of the site-facing half** (`cosign-dm-spec.md` §6.2), with the
> app's name in place of the site's, so that the one thing a person sees twice reads the same
> both times.

**What it is a boundary against, corrected in draft 2.** Draft 1 said the answer protects
nothing against a compromised Marble, because "a host app that has been taken over holds the
shares". That is wrong (§1): the process that renders other people's pictures and video holds
nothing, and cannot reach a share or a peer-taking call. So the realistic compromise — a bug in
media parsing, a malicious post, an injected library in the UI — is **exactly** the one this
answer stops, because that process can only ask the signer through a door that checks the
record.

> **The record MUST live in the signer process and MUST NOT be writable from the main process.**
> It is the one piece of this that a compromised UI must not be able to forge, and the boundary
> that makes that possible already exists.

What it does not stop is a compromise *of the signer process* — which holds the shares and can
do anything the account can. That is §9.1, and it is a much smaller target than draft 1 implied:
no media parsing, no web content, no third-party rendering.

## 4. Sending

> **Per-correspondent approval MUST NOT be asked.** The peer is a key the person chose by
> opening a conversation; asking again is the "nagging" COSIGN.md §5.3 forbids, and a prompt
> that appears for every new contact trains the person to dismiss it.

> **A send MUST follow the NIP-17 shape exactly**: a rumor that is never signed, a seal (kind 13)
> signed by the account and encrypted to the recipient, and a gift wrap (kind 1059) from a
> **fresh random key per message**, encrypted to the recipient. The account's own copy is sealed
> to the account and wrapped the same way, which under R4 is `private data` and not `messages` —
> so a client with only `messages` can send and then not read back what it sent, and the pane
> MUST NOT look broken when that is the case.

The seal is the only signature, and it is an ordinary FROST round (`signOwn`), so sending is one
signature plus two local encryptions plus one threshold round for the seal's encryption to the
recipient. Sending is the cheap direction.

## 5. Reading, and the thing that decides whether this is usable

> **Reading is one permission for all senders and MUST NOT be presented as narrowable** (R1).
> NIP-17's outer wrap comes from a one-time key the sender never reuses, so the device does ECDH
> against a key it has never seen and learns who sent the message only after the decryption
> succeeds. There is nothing to put on a list.

> **A reader MUST check that the seal's `pubkey` equals the rumor's `pubkey`**, and MUST discard
> the message otherwise. Nothing in Cosign can do this for a client: the wrap proves nothing
> about the sender, the seal is what binds them, and a client that skips the check accepts a
> message that says it is from anyone.

**The cost, which is the real design problem.** Every wrap has a one-time peer, so the device's
shared-x cache is never hit — I confirmed this against the code, and it is not a bug but the
point: `Kept` is keyed on the peer (`Phone.kt:1637`). So **each incoming message is a full
threshold round with a server**, at 3–6 seconds on Android. Fifty unread messages is minutes of
spinning, and an inbox that must be online to be read at all.

> **A client MUST NOT open a round per message in sequence.** Until batching exists (§8), a
> client MUST read the newest wraps first, MUST show what it has while the rest arrive, and MUST
> NOT block the pane on the whole inbox.

> **The signer process MAY keep a conversation key per correspondent, and the main process MUST
> NOT ever hold one.** Keys are kept under the grant that asked for them, not only under the
> peer, so that switching `messages` off, removing the grant, or reporting the device lost drops
> them — which today's peer-keyed map cannot do, because it is consulted before any gate
> (`Phone.kt:1637-1651`, `:1780`).

> **A key for the account's *own* key MUST NOT be kept at all.** This is the one the joint review
> found and it is the sharpest finding in it. A refresh moves shares and **keeps the group key**
> (COSIGN.md §7.3), so the conversation key with oneself never changes — ever. Keeping it would
> hand a removed, lost or stolen device a permanent, server-free decryptor for every piece of
> private data the account writes **in the future**, not merely what it already read: wallet
> state, mutes, drafts and app data are all self-encrypted and all public on relays. Draft 1's
> "drop every key when the epoch moves" buys nothing against it, because the key does not depend
> on the epoch. The cost of the fix is one round per unlock, which is today's behaviour.

So the rule is split by peer, like everything else in R4: **a correspondent's key may be kept, the
account's own may not.** That is also the honest version of draft 1's claim that persisting keys
is what makes an inbox usable — it is, for conversations with other people, and it must not be
done for the account's conversation with itself.

**On R8.** Draft 1's "a client MUST keep the conversation key" reads as a contradiction of R8,
which forbids any door handing out a shared secret, and the review was right to flag the wording.
The resolution is the process boundary: the signer derives and keeps the key, and **nothing
crosses `ISigner` but plaintext and ciphertext**. R8 is about what leaves the signer; this is
about what the signer remembers. The rule above says so explicitly so the two cannot be read as
being in conflict.

## 6. Private data

> **`private data` covers a decryption whose peer is the account's own key, and the encryption
> that writes it back** — mutes, bookmarks, private list items, drafts, and the account's own
> copies of sent messages. It is asked separately from `messages` and neither implies the other
> (R4).

Marble's *own* app data is not in this: it belongs in an app-key namespace, which no grant
reaches and which this document does not touch. What Marble needs `private data` for is the
**account's** private lists, which are the account's and not an app's.

> **Writing to self is covered by the same answer as reading it, and is gated by it** — the
> reason for one answer is that read-only would break muting, which is self-encrypted and
> ordinary. But draft 1 only wrote the *decrypt* side into §3's MUST, which left encryption to
> self ungated: `messages` alone would have been a write permission for private data. Both
> directions, with `peer == groupX`, need the `private data` answer.

> **Reading the account's own sent copy of a message needs *both* answers**, and a client MUST
> say so rather than show half a conversation. The wrap is from a one-time key, which is
> `messages`; the seal inside it is from the account to itself, which is `private data`. Draft 1
> said a client with only `messages` "can send and then not read back what it sent", which
> understated it: it cannot read back **any** of its own side, including from before the
> permission was given.

The protection against a *rewrite* of private data belongs on the signing path, where the kind is
visible — and the review is right that it does not exist yet and would not work as assumed:
`assess` compares **tags** (`policy.ts:46-55`, `:105`), while a private mute list keeps its
private half in encrypted `content`, so the private half can be emptied and the person is shown
"Mute list: reordered". That is a finding against the destructive check itself, it is recorded in
`no-server-history.md` §9, and **this document MUST NOT claim the protection until it exists.**

## 7. What a server sees, and what it must not be asked for

> **Unchanged from today and from R2**: a server answers a decryption partial to a live member
> device only, with a proof that the partial was made with the share the member list publishes
> (0.12.7), and never coordinates a decryption itself. A client MUST verify every proof before
> combining.

**The extension does not do that yet** (`extension/src/member/device.ts:189` combines
`res.points` with nothing calling `ecdhVerify`), so on a browser member a server's wrong partial
is a silent wrong key — which for a DM means an unreadable message that looks like a corrupt one.
**This document MUST NOT ship for the extension before that is fixed.**

> **A per-grant limit on decryption rounds MUST exist before an inbox is pointed at a server.**
> Today the only bound is a group-wide flood guard of 600 messages a minute meant for relays
> (`group.ts:177`). A DM inbox is the first thing in Cosign that legitimately asks for hundreds
> of decryptions in a burst, so the absence of a limit stops being theoretical: nothing
> distinguishes an inbox from a device enumerating every wrap addressed to the account for a year.

## 8. Batching, which this depends on and does not specify

One round per wrap is the thing that makes a first use painful, and the fix is to ask for many
partials in one request. That is a protocol change with its own spec, and two requirements
belong here because getting them wrong undoes work already done:

- **A batch MUST carry a proof per partial** (0.12.7's `ecdhProve`). A batch that returns a list
  of points with one proof, or none, reintroduces the unverified round the proofs just closed —
  and for an inbox the symptom is indistinguishable from a message that will not decrypt.
- **A batch MUST NOT let one request learn the shape of the inbox.** A server already sees how
  many wraps a device asks about; a batch makes that one number per sync rather than one event
  per message, which is better, and the request MUST NOT carry anything else about them.

There is a branch (`claude/ecdh-batch`) that predates the proofs. It MUST NOT be merged as it
stands.

## 9. What this does not protect against

1. **A compromised signer process.** It holds the shares and can do anything the account can.
   Draft 1 said this of the *host app*, which was wrong (§1): the main process — the one that
   parses other people's media — holds nothing, cannot reach a share, and can only ask through a
   door that checks the record. The target is the signer process, which renders no foreign
   content and whose attack surface is the relay traffic and the doors themselves.
2. **A removed device's cached conversations.** §5 asks clients to persist conversation keys,
   which means a device removed from the account keeps every conversation it had already opened,
   for ever. Dropping them on an epoch move (§5) covers *new* epochs and does nothing about what
   was already decrypted. This is the checklist's own tradeoff and it is a real one: persisting
   keys is what makes the inbox usable and what makes a stolen phone worse.
3. **Metadata, and it is worse in the send direction than draft 1 said.** Reading: a server sees
   N decryption rounds and their timing, against one-time keys that tell it nothing about who.
   **Sending: the peer is the recipient's real public key**, and a server must be told it to
   answer the round — so a server learns every person the account writes to, and when. That is
   not hidden by anything in this document, and blinding (app-keys §8) is no help, because the
   point being blinded is a counterparty's key the server may hold a list of. It should be said
   on any page that describes this as private messaging.
4. **The one-time key does not hide the recipient.** NIP-17's wrap is addressed to the account's
   own key by `p` tag, so relays know who receives; that is NIP-17's property, not Cosign's.
5. **An inbox needs a reachable server.** With no server answering, nothing new can be read —
   two member devices together can do it in principle (COSIGN.md §5.5) and that path is marked
   *not built*.

## 10. What this would change in COSIGN.md

- **§5.6**: a second caller for the decryption round — the library's own host — with R2's rules
  and §3's recorded answer, and that the proof of each partial is checked before combining.
- **§6.1**: the question's words, shared with the site-facing half, and that an app's own grant
  carries a recorded answer like any other.
- **§5.3**: that a per-correspondent prompt is not asked, and why.
- **A new section on reading**: the seal-matches-rumor check, as a MUST on clients, because
  nothing in the protocol can do it for them.

## 11. Still open

1. ~~**Whether `nip44Self`'s line should be enforced rather than drawn.**~~ **Answered by the
   code: it is already enforced**, by a process boundary, an AIDL surface that takes no peer, and
   three `signerOnly` checks (§1). The question was based on my misreading. What remains is not
   whether to enforce it but **not to breach it**: the rule in §1 forbids adding a peer-taking
   method to `ISigner`, and the Messages pane uses the signer's own NIP-55 door instead.
2. **Where a conversation key lives on each platform**, and whether dropping them on an epoch
   move is right or merely tidy. Android has the keystore; the extension has profile storage,
   which live finding #5 already calls out as plain.
3. **Whether the account's own sent copies should be read under `messages` after all.** R4 puts
   them in `private data` because they are sealed to self, which is correct and surprising: a
   person who allows "messages" and not "private data" sees half of every conversation. The
   alternative is a third answer, which is worse.
4. **The inbox's first run.** Even with batching, a year of wraps is a lot of rounds. There may
   need to be a "read from here" point, which is a product decision as much as a protocol one.
