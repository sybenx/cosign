# A member device's own app reading and sending DMs — proposal, first draft

**Status: proposal, for review. Nothing here is built.** Written as specification text so it can
be attacked. The site-facing half is settled in `~/igloo/cosign-dm-spec.md` (code-connected
sites, per-site keys, the grant, migration, push) and the rule both halves obey is
`~/igloo/cosign-decrypt-rule.md` (**R1–R8**). Neither is restated here; where this document needs
more it adds to them, and it may not contradict them.

## 1. What this is about, and the thing to understand first

Marble embeds the Cosign library. It is not an app asking a signer across an IPC boundary — **it
is the signer**, in its own process, holding the account's shares. So the words "first-party app"
mean something different here than they do in `app-keys.md` §4.1: there is no caller to
identify, no package name to check, no certificate to pin. The question is not *who is asking*
but **what the host of the library may do with the account, and whether the person is asked.**

**And the capability is already shipped.** `Phone.nip44(g, peer, text, encrypt)` is public
(`Phone.kt:1851`) and takes any peer, so a host app with the library can already decrypt
anything addressed to the account, today, using the grant the library makes for itself
(`connectApp(own, appName)`). What stops Marble doing it is that nothing calls it — not a check.

The library does draw a line, and draws it carefully in one place. `nip44Self`
(`Phone.kt:1769`) is **peer-less by design**, and its comment is the argument this document has
to answer:

> *"The other side is this account's own key, always — there is no peer to pass in, so this is no
> way to read anyone else's messages."*

So this proposal is not "add a capability". It is **"put rules around one that already exists,
and move a line the library drew on purpose."** That is a smaller change in code and a larger
one in what the account promises, which is the opposite of how it looks.

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

**What this does not do, stated because it is the obvious objection:** the answer is not a
security boundary against a compromised Marble. A host app that has been taken over holds the
shares; it calls `nip44` directly and the recorded answer is a row in its own storage. The
answer is a boundary against **Marble as written** — it makes reading DMs a thing the app does
because the person said so, auditable in the same list as everything else, and switchable off
without dismantling the account. §9 says what a compromised host gets, and it is everything.

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

> **A client MUST keep the conversation key it derives, per correspondent, in the same storage as
> the account's other secrets, and MUST drop every key for a correspondent when the account's
> epoch moves.** Then a *conversation* costs one round and a *message from a new person* costs
> one, which is the difference between usable and not.

This is a change from today's cache, which is in memory, ten minutes, cleared on screen-off, and
has no cap (`Phone.kt:1637-1649`, `:276`). Persisting conversation keys is what makes an inbox
readable offline, and it is also §9's first entry.

## 6. Private data

> **`private data` covers a decryption whose peer is the account's own key, and the encryption
> that writes it back** — mutes, bookmarks, private list items, drafts, and the account's own
> copies of sent messages. It is asked separately from `messages` and neither implies the other
> (R4).

Marble's *own* app data is not in this: it belongs in an app-key namespace, which no grant
reaches and which this document does not touch. What Marble needs `private data` for is the
**account's** private lists, which are the account's and not an app's.

> **Writing to self is covered by the same answer as reading it** — and the reason is that
> read-only would break muting, which is self-encrypted and ordinary. The protection against a
> rewrite belongs on the signing path, where the kind is visible, and is specified in
> `no-server-history.md` §9 rather than here.

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

1. **A compromised host app.** It holds the shares; it calls `nip44` with any peer; the recorded
   answer is a row in storage it controls. Everything the account can read, it can read. §3 is
   honest about this.
2. **A removed device's cached conversations.** §5 asks clients to persist conversation keys,
   which means a device removed from the account keeps every conversation it had already opened,
   for ever. Dropping them on an epoch move (§5) covers *new* epochs and does nothing about what
   was already decrypted. This is the checklist's own tradeoff and it is a real one: persisting
   keys is what makes the inbox usable and what makes a stolen phone worse.
3. **Metadata.** A relay sees that a device asked about N wraps; a server sees N decryption
   rounds and their timing. Neither sees who or what. A server that logs can tell how much the
   account is talking and when.
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

1. **Whether `nip44Self`'s line should be enforced rather than drawn.** The library could require
   a recorded answer inside `nip44` rather than trusting its host to ask — a check in the library
   is worth little against the host that embeds it, but it is worth something against the host's
   *mistakes*, which are likelier than its malice. Mine, and I lean towards enforcing.
2. **Where a conversation key lives on each platform**, and whether dropping them on an epoch
   move is right or merely tidy. Android has the keystore; the extension has profile storage,
   which live finding #5 already calls out as plain.
3. **Whether the account's own sent copies should be read under `messages` after all.** R4 puts
   them in `private data` because they are sealed to self, which is correct and surprising: a
   person who allows "messages" and not "private data" sees half of every conversation. The
   alternative is a third answer, which is worse.
4. **The inbox's first run.** Even with batching, a year of wraps is a lot of rounds. There may
   need to be a "read from here" point, which is a product decision as much as a protocol one.
