# Keykin: Refresh now

Draft 3 · 2026-11-02 · optional module of [Keykin Core](core.md) draft 8.1 · not built

"Refresh now" is the one ceremony that changes an account's structure. It re-deals every share, so
honest members' old pieces are destroyed and the new ones no longer combine with anything kept from
before. That is what makes replacing a server safe. It also adds or removes a helper, prints a new
paper, changes locks and relays, and makes new data and release keys.

**What it cannot do.** The key underneath stays the same, so pieces of the **same old epoch that
someone kept** still add up to it among themselves, for ever. A removed phone (3) plus the old paper
(2) is the key after a refresh just as before. So the old paper must be **destroyed** once the refresh
is done, and the app says exactly that, at that moment.

It is deliberately simple. It is started by hand. It runs only when **every member that stays** is
online at once, and every one of them confirms before anything changes. The paper is printed only
after everyone has confirmed. The old epoch keeps working until every member has moved. There is no
automatic run, no partial refresh, and nothing sealed in silence for someone to pick up later.

The bar is the same as the core's: an nsec in a password manager. Terms are the core's.

## 1. When it runs

- The person taps **Refresh now**. Apps SHOULD offer it after a device is reported lost, after a paper
  recovery, and when a server has been quiet for a week ("Your server at home has been quiet for a
  week"). They never run it without the person.
- **Before starting**, the device says that a new paper will be printed and that the person should
  **keep the old paper until the app says the refresh is finished** (a security display). It never
  says the old paper "stops working".
- It needs an approval (core §6.2): the starting device's lock, two devices with a typed code, a device
  with the paper, or a paper recovery session. In a recovery session the plan comes from the backup
  holder's app (on the new device) over the holder's own connection.

## 2. Who takes part

- The **plan** names the new epoch's members:
  - the **staying** members: every current member the plan does not remove;
  - the **new** members: servers, a helper, the new backup, and (rarely) devices joining at the same
    time;
  - the **leaving** members: any server, helper or backup it removes, and every device already
    reported lost.
- **Every staying member MUST be online and confirm.** One unreachable staying device or server stops
  the refresh. The person either brings it online or removes it: a device by reporting it lost (core
  §6.4) first, a server or helper by naming it as leaving.
- The **partner** is the second dealer, the second repair helper and the commit's co-signer. It is a
  staying server if one stays; if none does (every server dead), a second staying device; if there is
  none, the paper, scanned on the starting device. (A device plus the paper is 5 points: already the
  key, so this gives nobody anything new.) When the paper is the partner, the starting device opens the
  backup material with the release key, deals and receives deltas for the old backup's indices as if
  it were a staying member, uses those pending shares as the partner's, and destroys them at the
  commit; the old backup key is in `leaving`.
- The new epoch MUST satisfy the core's invariants: at least 3 servers, at most one helper, one backup.

## 3. The steps

1. **Plan.** The starting device sends `refresh_plan` to every staying and new member, sealed to each:

   ```jsonc
   { "type": "refresh_plan", "plan": "<16 random bytes, hex>", "from_epoch": "<epoch id>",
     "epoch": { "n": 4, "id": "<16 random bytes>" },
     "staying": [ <member entries as in the epoch record, with any new lock> ],
     "new":     [ <member entries for joining servers, helper, devices, and the new backup> ],
     "leaving": [ "<member key>", … ],
     "relays": [ … ],
     "partner": "<member key of the partner, or the backup key when the paper is the partner>",
     "approval": { /* core §6.2, over "refresh" ‖ SHA-256(JCS(plan without approval)) */ } }
   ```

   New members' indices are derived as for changes (core §3.2), with the new epoch id. A server MUST
   check:
   - the approval and the invariants;
   - that `from_epoch` is its current epoch;
   - that `leaving` lists every removal it knows of;
   - that `staying` keeps every device added by a change of this epoch that is not removed;
   - that the partner is a staying server whenever one stays.

   It holds **at most one plan**: while it holds one, it answers any other with `error busy` and
   refuses new adds (core §3.2). A `remove` aborts the plan (step 8).
2. **Deal.** The starting device and the partner each deal a random degree-3 polynomial with zero
   constant term. Each publishes its commitments (exactly 4 points, the first the identity) to every
   member, and seals to each staying member the delta for each of its indices, live or through inboxes
   (core §7.1).
3. **Check.** Each staying member checks every delta against its dealer's commitments
   (`δ·G == Σ D_k·i^k`). It adds both, keeps the result as its **pending** share, and checks it against
   `C' = C + D + E`, the two dealers' commitments added (`C'0 = C0`). If a delta does not check, the
   member sends `refresh_refuse {plan, dealer}` to the starting device and every server, and **any
   refusal aborts the plan**. A dealer that sent bad deltas is named, and the person decides what to do
   about it.
4. **New members.** Each new server, helper or device gets its pending shares by repair (core §4.2
   step 3) on the new polynomial, with the starting device's 3 pending shares and the partner's pending
   share(s) as helpers. A new device or helper joins through the core's handshake and typed check (core
   §4.1); a new server joins with its member key from its announcement. Each checks its shares against
   `C'`.
5. **Confirm.** Every staying and new member (not the backup) sends `refresh_ok {plan, pending: [P_i…]}`,
   with a detached signature, to the starting device and every server, once its pending shares verify.
   New devices also confirm their locks here. The starting device sends the new release key to every
   device and server and the new data key to every device, sealed, live or through inboxes.
6. **Paper, only now.** When the starting device holds a `refresh_ok` from every staying and new member,
   it makes the new paper exactly as core §4.3, on the pending shares (with the partner as the second
   repair helper):
   - it checks the backup's shares with the secret it holds;
   - it wraps them and the new data key and signs the inner layer;
   - it sends the material to every server and device; each server answers `backup_held {plan, hash}`;
   - it has the person print the paper and **show it is readable**.

   A refresh for an account with no paper skips this step. The backup itself never confirms or adopts
   anything: the person's read-back is its confirmation.
7. **Commit.** The starting device drafts the new epoch record:
   - `C'`;
   - the members;
   - `removed`, extended with the leaving keys and every device removed by a change in the old epoch;
   - the new `backup` hash;
   - in `refresh`, the plan's approval, every `refresh_ok` and every server's `backup_held`.

   It gets the record signed by itself and the partner using **pending** shares, and sends it to every
   member. A server co-signs it only within 24 hours of its own `refresh_ok`, and only if it still holds
   the plan.
8. **Abort.** Before the commit, the plan ends if:
   - the starting device, or any device of the account with an approval (core §6.2), sends
     `withdraw {plan}`, so a stuck refresh never needs the device that started it;
   - any `refresh_refuse` arrives;
   - a `remove` arrives;
   - a server's own clock runs out:
     - 2 hours (reference) after the plan reached it, if it has not sent `refresh_ok`;
     - 48 hours after its `refresh_ok`, if no record has come.

     It then tells every member (`refresh_dropped`).

   Every member then destroys its pending shares and any new keys it received. A device drops pending
   shares **only** on `withdraw`, `refresh_refuse`, `remove` or a server's `refresh_dropped`, never on
   its own clock. Because a server co-signs only within 24 hours and drops only after 48, a server can
   never drop a plan whose record is still being made. If the paper was already printed and the plan
   aborts, the app says the new paper is void and **the old paper is still the one to keep**.

## 4. Moving over

- A member **adopts** the new epoch record once it checks it (core §3.4, with the `refresh` evidence).
  It then sends `adopted {epoch}`.
- A commit ends any recovery wait or session for a backup that is not in the new record; servers never
  release the new epoch's keys to an old backup.
- **The old epoch stays valid until every member has moved, and at most 7 days.** Until a member has
  seen `adopted` from every member of the new record other than the backup, or 7 days have passed since
  the commit, whichever comes first, it keeps its old share, release key and backup material, and signs
  rounds in whichever epoch the request names (core §5.1: all shares of one round are of one epoch).
  Servers refuse old-epoch rounds from leaving members, exactly as they refuse removed ones.
- Then each member destroys its old share, the old release key and the old backup material. Devices
  keep old data keys to read old data. A member that had not adopted by then joins again.
- **Only now** does the app tell the person to **destroy the old paper** (a security display), once
  every server has sent `adopted`. Honest members hold no old pieces any more, so a leaving server's or
  removed device's old pieces combine with nothing an honest member has. **They still combine with each
  other and with the old paper**: that is why it must be destroyed.
- A member that was in the plan but missed the commit (it crashed after confirming) fetches the record
  and its deliveries when it is back (core §7.1) and adopts. A member that lost its pending shares joins
  again.

## 5. What it does not do

- It never runs by itself, never on a schedule, and never with a member missing.
- It never seals shares to someone who isn't there to confirm: new members get theirs by repair while
  online, and the paper is checked by the person at print time, after everyone has confirmed.
- It never changes `g`, `role` or `origin`.

## 6. Security properties, and limits

**What it gives.**

- After the old epoch retires, honest members hold no old pieces, so a removed device or a leaving
  server can no longer find an honest partner, and new private data is under a new data key.
- Servers change only here, and the re-deal means old and new server pieces never add up to 4.
- It works even when every server is dead: a second device or the paper takes the partner's place.
- It cannot get stuck: any device with an approval can withdraw it, and servers' clocks free them.
- Nothing is silent: everyone who stays confirms, the person sees the paper warnings, and the paper is
  read back.

**What it doesn't.**

- **Everyone must be online.** One dead staying member blocks it until removed. A dead *device* must be
  reported first, which needs an approval (a lock, two devices, or the paper).
- **A thief who gets an approval** (the owner's biometrics, two of the owner's devices, or a device
  plus the paper) can run a refresh that drops the owner's devices. That is already the key, so it is
  no worse than the core.
- **A dealer that sends bad deltas can stop a refresh**, again and again. It is named each time; if it
  is a server, the person removes it in the next refresh with a different partner.
- **The starting device sees the new backup's shares** while it makes the paper (core §4.3). A
  compromised starting device can keep the new paper's power. It already holds the key with the paper
  at that moment.
- **Old pieces kept by anyone stay valid among themselves, for ever.** A removed device plus the old
  paper, or plus a dishonest leaving server's kept share, is the key after any number of refreshes.
  Destroying the old paper is the person's job; the app says so when the time comes.

## 7. Messages

| `type` | From → to |
|---|---|
| `refresh_plan` | starting device → every staying and new member |
| `refresh_deal` | dealer → members (commitments; deltas sealed per member) |
| `refresh_refuse` | member → starting device and servers |
| `refresh_ok` | member → starting device and servers |
| `backup_held` | server → starting device |
| `withdraw` | any device with an approval → members |
| `refresh_dropped` | server → members |
| `record` | starting device → members (the new epoch record) |
| `adopted` | member → members |

## 8. Test vectors

These are in the core's vectors (`vectors/vectors.md`, case 12):

- an honest refresh;
- an honest refresh with every server dead, first with a second device as partner, then with the
  paper as partner;
- a bad delta: any refusal aborts the plan;
- a commit missing one `refresh_ok` or one `backup_held` is refused;
- two plans: the second is refused with `busy`;
- a `remove` aborts a plan;
- a plan that drops a device added in this epoch is refused;
- a stuck plan is withdrawn by another device with an approval;
- server clocks: no co-signing after 24 hours, dropping only after 48 hours;
- a server swap where the old server's share does not fit `C'`;
- old-epoch rounds are accepted until everyone adopts or 7 days pass, then refused;
- a commit ends a recovery that was using the old backup.

## Changes in draft 3

From red-team round 8:

- the paper is printed only after everyone confirms, and "destroy the old paper" is shown only once
  every server has adopted (H2);
- server clocks start at the plan (2 hours, or 48 hours after confirming), and any device with an
  approval can withdraw (H1);
- a partner (a second device, or the paper) replaces the server when none stays (H3);
- devices drop pending shares only on an explicit signal, and servers co-sign only within 24 hours and
  drop only after 48 (M1);
- servers check that a plan keeps every device added in the epoch (M2);
- the paper material reaches every server before the commit (`backup_held`) (M3);
- any refusal aborts (L2);
- a commit ends a recovery that used the old backup (L1);
- a recovery's plan comes from the holder's app (L7).
