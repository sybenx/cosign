# An app key of its own — proposal

**Status: proposal, for review. Nothing here is built.** Written as specification text so it
can be attacked. It is not part of [COSIGN.md](COSIGN.md) until it has been reviewed and the
author agrees; §11 lists what it would change there, and §12 what it costs the other two
proposals in flight.

**What it is for.** Marble keeps the user's notes as encrypted packs
(`~/igloo/marble-notes-sync-v3.md`, option B+). It wants two things Cosign cannot give it
today: a key that **only Marble's own clients** can reach, so that no site or app the user
has merely connected can read the notes; and a key that **signs the packs on the device**,
with no FROST round per pack and no link to the user's npub. It also wants both to **rotate
when a device is removed**, so that a device taken out of the account stops being able to
read or write.

This proposal gives Cosign a general mechanism — an **app key**, derived per namespace and
per epoch, reachable only by callers a device can identify — and makes Marble its first and
only caller. It needs no new cryptography and no change to any message on the wire.

**One thing to read before anything else.** The construction Marble asked for,
`K_e = HKDF(to-self shared x, "marble/notes/v1/" + epoch)`, does **not** rotate, and the
property it is relied on for is false. The to-self secret is the account's key against
itself; a refresh moves everybody's shares but keeps the same account key, so that secret is
the same in every epoch, for ever. Any device that ever held it can compute every future
epoch's key by incrementing the counter. A removed device would keep reading new notes forever.
§3 replaces it with something that does rotate, for the same cost.

---

## 1. What an app key is

An **app key** is a secret that:

- is derived from the account's key by a **threshold round**, so no single member can produce
  it and no member holds it at rest;
- belongs to a **namespace** (`marble/notes/v1`) and an **epoch** (the account's current
  epoch, §7.3), so it changes when the account's membership changes;
- is reachable only through a **first-party call on a device** (§4), never over NIP-46 and
  never through a site's or app's grant;
- yields, by HKDF, as many keys as the namespace needs: a content key, a tag key, and a
  **signing key** that is an ordinary Nostr secret key (§5).

It is **not** a share of the account's key, carries no points, and signing with it is not
signing as the user.

## 2. The label point

For a namespace `ns` and epoch `e`, the label is the byte string

```
cosign-app-key:v1:<ns>:<epoch>
```

and the **label point** `P(ns,e)` is that label mapped onto secp256k1 by try-and-increment:

```
for i = 0, 1, 2, …:  x = SHA256("cosign-app-key-point:v1" ‖ label ‖ i)
                     if 02‖x is a point on the curve: P = that point, stop
```

- **`P` MUST be obtained by hashing to the curve, never as `h·G` for a hash `h`.** If the
  discrete log of `P` were known, then `s·P = h·(s·G)` — computable by anyone holding the
  account's **public** key and `h`, which is everyone. That one substitution would turn this
  whole mechanism into a public value.
- The label and therefore `P` are public. Nothing about them is a secret; the secret is
  `s·P`, which needs the key.

## 3. Deriving it, and why that rotates

The app key's root is the threshold ECDH of the account's key with the label point:

```
x(ns,e) = s · P(ns,e)        taken as the x-coordinate, 32 bytes
K(ns,e) = HKDF-Extract(SHA-256, salt = "cosign-app-key:v1", ikm = x(ns,e))
```

This is the round Cosign already runs for decryption (§5.6): each member taking part returns
`λ_i · s_i · P` for its shares and the coordinator adds them (`ecdhPartial`, `ecdhCombine`).
**The only thing that differs from reading a message is which point is asked about.** No new
message, no new maths, no server change.

**Why it rotates, where the to-self secret does not.** `x(ns,e)` can only be computed by a
set of members that reaches the threshold *in the epoch they are in*. A device that has been
removed:

- cannot run a round — it is worth 3 points, the threshold is 4, and every honest member
  refuses it from the moment it is reported (§7.2);
- cannot derive the new epoch's key from the old one — the two are unrelated values, not a
  counter apart.

And a device that is **still** a member can recompute **any** epoch's key, old ones included,
because `x(ns,e)` depends on the account key and the label and not on which shares are
current. Two consequences, both good:

- **nothing has to be re-encrypted when the epoch moves.** Marble's option B budgeted for
  re-encrypting old packs lazily; that cost disappears. Old packs stay readable by the
  members that remain, for ever, with one round each.
- **a removed device keeps what it already had.** It can still read the packs of the epochs
  it lived through, because it holds those keys already. Rotation stops it reading what comes
  **next**; it does not reach back. §9 says what that means.

## 4. Who may ask: the first-party rule

> **A device MUST answer an app-key derive call only for a caller it has identified itself,
> by a platform mechanism, against a list compiled into that device's own build.** It MUST
> NOT answer one for a site or app that merely holds a grant, and the call MUST NOT exist
> over NIP-46 at all.

- **Android.** The call arrives over the signer's AIDL or content provider. The device takes
  the calling UID, resolves it to a package name **and the digest of the certificate that
  signed that package**, and matches both against the compiled list. A package name alone is
  not an identity: anyone may publish an app by that name.
- **The browser extension.** Only its **own** extension pages, or an exact HTTPS origin on
  the compiled list (Marble asks for `notes.marble.syb.lol`). Scheme, host and port MUST all
  match; no wildcards, no subdomain matching, and never a page the extension did not load
  itself.
- **A desktop host** (the Mac app) calls it in its own process, which is first-party by
  construction. A host MUST NOT expose it to anything it loads — a webview is not the host.
- **NIP-46.** Never. A server cannot tell one app from another, and a signer key is shared by
  every site that connects by code (§6.1). A derive call answered over NIP-46 would hand the
  namespace to whoever reached that key, which is the hole this mechanism exists to close.

**No user approval is asked for, and none would help.** The question "may this app derive its
own key?" is not one a person can answer better than the platform can: the honest version of
it is "is this really Marble?", and the package signature answers that. A prompt here would
be the key-management nagging §0a of
[progressive-accounts.md](progressive-accounts.md) exists to abolish.

**The caller never sees `x` or `K`.** A device hands out only what the namespace is for: the
content key for a pack, or a signature. A first-party caller that *is* the device's own host
(the Mac) holds them by construction; one that is a separate process (Marble on Android, a
page in the extension) MUST be given derived material for the operation it asked for, not the
root.

## 5. What the namespace gets

From `K = K(ns,e)`, with HKDF-Expand and SHA-256:

| | info | what it is |
|---|---|---|
| content key | `"content"` | 32 bytes, the NIP-44 v2 key for packs of this epoch |
| tag key | `"tag"` | 32 bytes, for the `d` values of this epoch's addresses |
| signing key | `"sign"` | 32 bytes → a secp256k1 secret, reduced mod *n*, rejecting 0 |
| Blossom key | `"blossom"` | as the namespace needs it |

**The signing key is an ordinary Nostr key.** Each device derives the same one and signs
packs locally in about a millisecond: no round, no server, nothing signed by the account. Its
public key `pk(ns,e)` is how the packs are found, so **no pointer is published anywhere** —
every device that can derive the key knows the address, and a device that cannot derive it
learns nothing from a relay but an unfamiliar pubkey. That answers H2 of Marble's review
(there is no key event to lose, race or overwrite) by having no event at all.

**The tag key MUST rotate with the epoch too.** Marble's draft keeps one stable tag key from
epoch 0. A removed device would then go on knowing every address for ever — not able to read
new packs, but able to enumerate them, and able to write junk to the same addresses under the
old signing key. Rotating it costs the readers one extra walk back, which they do anyway.

## 6. When the epoch moves

- The epoch is the account's own (§7.3). **Nothing new is published and nothing new has to be
  learned**: every member already knows the epoch and the time it began (`epochAt`), from the
  refresh it took part in or from the member record it holds.
- A refresh happens after every removal, after a paper restore, and periodically (§7.7). So
  "the epoch moves when a device is removed" needs no new trigger: it already does.
- **Writes move at once.** A device MUST write new packs only under the current epoch's
  signing key, and MUST stop writing under the previous one as soon as it sees the new epoch.
- **Reads walk back.** A reader follows `pk(ns,e)`, then `pk(ns,e-1)`, and so on, as far as
  the namespace keeps history.
- **A pack under an old epoch is only history, and only until the moment that epoch ended.** A
  reader MUST reject a pack signed by `pk(ns,e-1)` whose `created_at` is later than
  `epochAt(e)`. Without that rule a removed device could go on writing convincing packs under
  the key it kept; with it, anything it writes after the moment it was removed is ignored by
  every honest reader. This is the one rule in this document that an implementation gets wrong
  silently, because nothing fails: the forged packs simply look old.

## 7. What a server sees, and hiding the label

The round is the one servers already answer, so a server sees: a device asking for a point,
the point, and its own partial. Because the label is public, a server can recognise it — it
learns "this device derived Marble's notes key for epoch 7", which is metadata about which
app the user runs, not about the notes.

A device **SHOULD blind it**: pick random `r`, ask about `r·P`, and multiply the result by
`r⁻¹`.

```
ask for      Q = r · P(ns,e)        (x-only on the wire, as today)
receive      s · Q
compute      x = (r⁻¹ · (s · Q)).x = (s · P).x
```

The server then sees a point it cannot distinguish from any other decryption, the
arithmetic is one inversion and two multiplications, and nothing on the wire changes. (The
x-only form loses the sign of the point, which does not matter: both lifts give the same
x-coordinate for `s·P`.)

## 8. Where this sits with the rest of Cosign

- It is **not** a grant and MUST NOT be reachable by one (§4). Removing every site's access
  changes nothing about it; removing a **device** is what takes it away.
- It needs **no change to any server**. A server answering the round cannot tell an app key
  from a message being read, which is why the first-party rule has to live on the device.
- Two devices can derive it **with no server at all**, by the device-to-device round of
  §5.5 — the same path, the same rule.
- The account's own to-self secret (`peerX = groupX`) stays what it is: reachable by anything
  with decrypt access, which is why no namespace key may be derived from it (§0 and C2 of
  Marble's review).

## 9. What it does not protect against

Stated plainly, because a mechanism like this invites more faith than it has earned.

1. **A breached device in the current epoch.** It derives everything the namespace has and
   signs anything it likes. There is no key separation inside a device; a device that is
   compromised is compromised for its notes too. The only answer is removing it, which
   rotates the epoch.
2. **A removed device's past.** It keeps every key it ever derived, so it can read the packs
   of the epochs it lived through, for ever, wherever it kept them. Only new epochs are
   closed to it. If that matters for a particular note, the note has to be rewritten — which
   is a Marble decision, not something this mechanism can do.
3. **A stolen device plus one cooperating member.** 3 points and 1 is the threshold: a thief
   with an unlocked device and any one server derives the namespace, exactly as they can sign
   (§12 of COSIGN.md, the accepted baseline).
4. **An XSS on an allow-listed origin.** For the extension's web caller, a script injected
   into `notes.marble.syb.lol` is first-party as far as the browser is concerned, and so as
   far as this rule is concerned. It gets what the page gets. Marble's own draft assumes an
   epoch bump after such a fix, which is the right response and it is not automatic: somebody
   has to notice.
5. **Servers keeping history.** Everything a server ever kept, it keeps. The packs are not
   under the account's npub and do not go through a server at all, so a server sees only the
   derive rounds — and with §7's blinding, not even which namespace. But the archive of
   everything the account *did* sign stays as it is (§5.4), for ever.
6. **Relays.** They see an unfamiliar pubkey writing packs: their number, their size, their
   timing, and the IP they came from. Nothing here hides that, and a relay that correlates
   two identities by IP and time will do so.
7. **One operator with several servers.** Servers together are 3 points and cannot reach the
   threshold, so an operator alone derives nothing — but an operator who also has a stolen
   device is case 3.
8. **Someone who can make a device call it.** The first-party rule is as strong as the
   platform's answer to "who is calling": a package signature on Android, an origin in a
   browser. On a rooted phone, or in a browser whose extension has been replaced, that answer
   is worth what the device is worth, which is case 1.

## 10. Questions this leaves open

1. **Does the namespace list belong in the build, or in the account?** Compiled in (as §4
   says) means adding a first-party caller needs a release of the device software, which is
   slow but has no attack surface. In the account it would be a signed member record entry —
   faster, and a new thing for a compromised device to write to.
2. **Should a second namespace exist at all yet?** One caller, one namespace, is the safest
   first version. The mechanism is general; the list should not be.
3. **How far back do readers walk?** Every epoch since the account began is a round each. A
   namespace that writes a checkpoint per epoch would bound it; Marble has checkpoints already.
4. **Should the derive round require the device's lock?** It is not a granting action (it
   hands out no shares), but it is "read everything in this namespace". My instinct is no —
   it happens whenever notes sync, and a prompt would be constant — but a once-a-day lock,
   like a session, is arguable.

## 11. What this would change in COSIGN.md

- **§5.6**: a second use for the decryption round — an app key against a label point — with
  the hash-to-curve requirement and the blinding recommendation of §7.
- **§6.2**: a sentence saying an app key is not a grant and no grant reaches one.
- **§6.3, §6.4**: the first-party rule of §4, per door, and that NIP-46 has no such call.
- **§7.3**: that a refresh rotates every namespace's keys as a consequence, and the
  `created_at` cut-off of §6 that makes the rotation mean something.
- **§12**: the properties of §9, especially that a removed device keeps its past.

## 12. Conflicts with the other two proposals in flight

- **[progressive-accounts.md](progressive-accounts.md).** At its §3.1 and §3.2 the whole key
  lives on one device. There, an app key is a local computation, not a threshold round, and
  **none of the rotation in §3 means anything**: the device can derive every epoch of every
  namespace by itself, for ever, and so can any copy of that key. A namespace MUST NOT be
  told that rotation protects it until the account is split (§3.3 there). The derive call
  should refuse, or say plainly what it is, on a whole-key device.
- **[user-verification.md](user-verification.md).** No conflict, and one thing to keep
  straight: the derive call is **not** in the granting class (§4.2 there) and needs no UV
  assertion. If the open question of §10.4 here is ever answered "yes, ask for the lock", it
  becomes an `approve`-shaped action and belongs in that document's table rather than this one.
- **The archive.** Packs are not events of the account's, so they never enter the archive and
  the destructive policy never judges them. That is the intent (H1 of Marble's review: an app
  that can sign as the user cannot touch the notes) and it is also the trade: **nothing holds
  a mass overwrite of the notes for approval.** Only the namespace's own checkpoints protect
  against that, and they are Marble's to design.
