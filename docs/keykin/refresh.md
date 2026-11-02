# Keykin: Refresh now

Draft 1 · 2026-11-02 · optional module of [Keykin Core](core.md) draft 7 · not built

"Refresh now" is the one ceremony that changes an account's structure. It re-deals every share, so
the pieces of removed devices and servers stop fitting the key. It also replaces servers, adds or
removes a helper, prints a new paper, changes locks and relays, and makes new data and release keys.

It is deliberately simple. It is started by hand. It runs only when **every member that stays** is
online at once, and every one of them must confirm before anything changes. The old epoch keeps
working until every member has moved. The paper is reprinted and checked as part of it. There is no
monthly automatic run, no partial refresh, and nothing sealed in silence for someone to pick up later.

The bar is the same as the core's: an nsec in a password manager. Terms are the core's.

## 1. When it runs

- The person taps **Refresh now**. Apps SHOULD offer it after a device is reported lost, after a paper
  recovery, and when a server has been quiet for a week ("Your server at home has been quiet for a
  week"). They never run it without the person.
- **Before starting**, the device shows that the paper will be reprinted and **the old paper will stop
  working once the refresh finishes** (a security display). The person can stop there.
- It needs an approval (core §6.2): the starting device's lock, two devices with a typed code, a device
  with the paper, or a paper recovery session.

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
- The new epoch MUST satisfy the core's invariants: at least 3 servers, at most one helper, one backup.

## 3. The steps

1. **Plan.** The starting device sends `refresh_plan` to every staying and new member, sealed to each:

   ```jsonc
   { "type": "refresh_plan", "plan": "<16 random bytes, hex>", "from_epoch": "<epoch id>",
     "epoch": { "n": 4, "id": "<16 random bytes>" },
     "staying": [ <member entries as in the epoch record, with any new lock> ],
     "new":     [ <member entries for joining servers, helper, devices; indices from next free> ],
     "leaving": [ "<member key>", … ],
     "relays": [ … ],
     "dealer_server": "<member key of one staying server>",
     "approval": { /* core §6.2, over SHA-256(JCS(plan without approval)) */ } }
   ```

   A server MUST check the approval and the invariants, and that `from_epoch` is its current epoch.
   It holds **at most one plan**: while it holds one, it answers any other with `error busy` and
   refuses new adds (core §3.2). A `remove` aborts the plan (step 8).
2. **Deal.** The starting device and the named server each deal a random degree-3 polynomial with zero
   constant term. Each publishes its commitments to every member, and seals to each staying member the
   delta for each of its indices. Deltas travel live or through inboxes, never on relays.
3. **Check.** Each staying member checks every delta against its dealer's commitments
   (`δ·G == Σ D_k·i^k`). It adds both, keeps the result as its **pending** share, and checks it against
   `C' = C + D + E`, the two dealers' commitments added (`C'0 = C0`). A bad delta is answered with
   `refresh_refuse {plan, dealer, delta}`. The delta it carries is a point of a zero-constant polynomial
   and reveals no share, so any member can check the claim. A proven refusal aborts the plan.
4. **New members.** Each new server, helper or device gets its pending shares by repair (core §4.2
   step 3) on the new polynomial, with the starting device's 3 pending shares and the named server's
   pending share as helpers. A new device or helper joins through the core's handshake and check (core
   §4.1); a new server joins with its member key from its announcement. Each checks its shares against
   `C'`.
5. **New paper.** The starting device makes a new backup key pair and the paper exactly as core §4.3,
   on the pending shares. It checks the backup's shares with the secret it holds, wraps them and the new
   data key, signs the inner layer, and has the person print the paper and **show it is readable**. A
   refresh without a paper (an account that never had one) skips this step.
6. **Confirm.** Every staying and new member sends `refresh_ok {plan, pending: [P_i…]}`, with a
   detached signature, to the starting device and every server, once its pending shares verify. New
   devices also confirm their locks here. The starting device sends the new release key to every device
   and server and the new data key to every device, sealed, live or through inboxes.
7. **Commit.** When the starting device holds a `refresh_ok` from **every** staying and new member, it
   drafts the new epoch record:
   - `C'`;
   - the members;
   - `removed`, extended with the leaving keys and every device removed by a change in the old epoch;
   - the new `backup` hash;
   - in `refresh`, the plan's approval and every `refresh_ok`.

   It gets the record signed by itself and the named server using **pending** shares. That signature
   proves the new shares work, and every member can check that everyone confirmed. The device sends the
   signed record to every member.
8. **Abort.** Before the commit, the plan ends if:
   - the starting device sends `withdraw {plan}`;
   - a proven `refresh_refuse` arrives;
   - a `remove` arrives;
   - the plan is not committed within 1 hour (reference).

   Every member then destroys its pending shares and any new keys it received, and servers are free
   for another plan. A server MUST NOT drop a plan it confirmed for any other reason, and MUST NOT
   co-sign the new record after it has dropped the plan.

## 4. Moving over

- A member **adopts** the new epoch record once it checks it (core §3.4, with the `refresh` evidence:
  the approval and a `refresh_ok` from every member the record lists). It then sends `adopted {epoch}`.
- **The old epoch stays valid until every member has moved.** Until a member has seen `adopted` from
  every member of the new record, it keeps its old share, release key and backup material, and signs
  rounds in whichever epoch the request names (core §5.1: all shares of one round are of one epoch).
  Servers refuse old-epoch rounds from leaving members, exactly as they refuse removed ones.
- When every member has adopted, each destroys its old share, the old release key and the old backup
  material. Devices keep old data keys to read old data. **From then on, the old paper and every
  leaving or removed member's pieces fit nothing.**
- A member that was in the plan but missed the commit (it crashed after confirming) fetches the record
  and its deliveries when it is back, as the core says (§7.1), and adopts. Its pending shares were kept,
  so this works for as long as it kept them; a member that lost them joins again.

## 5. What it does not do

- It never runs by itself, never on a schedule, and never with a member missing.
- It never seals shares to someone who isn't there to confirm: new members get theirs by repair while
  online, and the paper is checked by the person at print time.
- It never changes `g`, `role` or `origin`.

## 6. Security properties, and limits

**What it gives.**

- After the commit, the pieces of removed devices, leaving servers and the old paper stop fitting.
  This closes the core's "between refreshes" limits: a removed device plus a bad server, a removed
  device plus the paper, and old data keys for new data.
- Servers change only here, and the re-deal means old and new server pieces never add up to 4.
- Nothing is silent: everyone who stays confirms, the person sees the paper warning, and the paper is
  read back.

**What it doesn't.**

- **Everyone must be online.** One dead staying member blocks it until removed. A dead *device* must be
  reported first, which needs an approval (a lock, two devices, or the paper).
- **A thief who gets an approval** (the owner's biometrics, two of the owner's devices, or a device
  plus the paper) can run a refresh that drops the owner's devices. That is already the key, so it is
  no worse than the core.
- **A member that loses its pending shares between confirming and adopting** must join again.
- **The starting device sees the new backup's shares** while it makes the paper (core §4.3). A
  compromised starting device can therefore keep the new paper's power. It already holds the key with
  the paper in that moment.
- **Old pieces copied before the refresh** (a removed device's shares, an old paper) stay valid for
  signing only until every member has adopted, and only with members that still hold old shares.

## 7. Messages

| `type` | From → to |
|---|---|
| `refresh_plan` | starting device → every staying and new member |
| `refresh_deal` | dealer → members (commitments; deltas sealed per member) |
| `refresh_refuse` | member → starting device and servers |
| `refresh_ok` | member → starting device and servers |
| `withdraw` | starting device → members |
| `record` | starting device → members (the new epoch record) |
| `adopted` | member → members |

## 8. Test vectors

These are in the core's vectors file, under "refresh":

- an honest refresh;
- a bad delta proven and the plan aborted;
- an unproven refusal ignored;
- a commit missing one `refresh_ok`, refused;
- two plans, the second refused `busy`;
- a `remove` aborting a plan;
- a server swap where the old server's share does not fit `C'`;
- old-epoch rounds accepted until everyone adopts, then refused.
