// A Kotlin device (step B1, growing): loaded from a device's state as the TS reference writes it
// (device/node.ts `snapshot()`), checked as core §4.4's handover step 2 says, and able to sign everyday
// events with any seated server over relays. Joins, changes and Upkeep follow.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

/** Sigmas a joining device keeps from senders other than its inviter (the servers are known only from the welcome). */
private const val SIGMAS_MAX = 256
/** Deliveries kept for redeals not yet known (review 13 M1): in all, per redeal, per sender; and for how long. */
private const val PENDING_MAX = 512
private const val PENDING_PER_REDEAL = 8
private const val PENDING_PER_SENDER = 16
private const val PENDING_TTL_S = 7 * 86400L
/** Change events taken from one message, and kept refused for later (review 13 H1). */
private const val CHANGES_PER_MESSAGE = 1024
private const val REFUSED_MAX = 256

class Device(val sk: ByteArray, val recEv: Event, val rec: JSONObject, changes: List<Event>, ids: List<String>, shares: Map<Long, BigInteger>, private val net: RelayNet,
             private var baseDk: String = "", dkSeeds: List<String> = emptyList()) {
    val pub: String = Secp.Reference.pub(sk)
    val g: String = rec.getString("g"); val epochId: String = rec.getJSONObject("epoch").getString("id")
    private val env = Envelope()
    /** The change set in force (§3.2), and the ones refused for now (kept: a later change may admit them). */
    @Volatile var changes: List<Event> = changes; private set
    private var refused: List<Event> = emptyList()
    @Volatile var view: MembershipView = Membership.compute(rec, changes); private set
    @Volatile var state: ShareState; private set
    val ids: Set<String> get() = state.ids
    val shares: Map<Long, BigInteger> get() = state.shares
    val ctx: RoundContext get() = state.let { RoundContext(g, epochId, it.hash, it.C) }
    @Volatile var wiped = false; private set
    private val dkSeeds = ArrayList(dkSeeds)
    /** Release seeds by redeal id (and `base`, §7.2), and the deliveries waiting for their redeal (§6.7.1). */
    private val releaseSeeds = HashMap<String, String>()
    private val pending = HashMap<String, LinkedHashMap<String, JSONObject>>()
    /** Paper values kept per redeal until the current paper's item is verified (§6.7.1 step 3). */
    private val kept = HashMap<String, JSONObject>()
    private val paperVerified = HashMap<String, Boolean>()
    /** The redeals whose paper values this device keeps (until the paper item is verified, or re-issued). */
    val keptRedeals: Set<String> get() = synchronized(this) { kept.keys.toSet() }
    val notices = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
    /** Every state this device has held, oldest first (core §4.5: older keys read older data). */
    private val dkHistory = ArrayList<List<String>>()
    val members = Members()
    /** A site's NIP-46 request a watching server kept for us (Doors §3.3): the home takes it. */
    @Volatile var onSiteRequest: ((JSONObject) -> Unit)? = null
    /** Called with this device's state, as `snapshot()` writes it, after every change: the app stores it
     *  where it is never backed up or synced (core §4.5), and loads it with `fromSnapshot` (review 13 M5). */
    @Volatile var persist: ((String) -> Unit)? = null
    private val gone = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
    /** The snapshot this device was loaded from: what Kotlin doesn't use yet (backup material, push keys, a
     *  lock) is written back as it was, so nothing a TS device kept is lost in a round trip. */
    private var carried = JSONObject()
    init {
        // §4.4 step 2: a current device holding exactly these indices, every share on the commitment at
        // this state (the record's plus each applied redeal's D), which rebuilds from this device's points.
        val C = Upkeep.commitmentAt(rec, view, ids)
        val me = view.members.firstOrNull { it.key == pub }
        if (me == null || me.kind != "device" || me.shares.sorted() != shares.keys.sorted()) refuse("not_member", "not a current device holding exactly these indices")
        Upkeep.checkOwnShares(g, shares, C, true)
        state = ShareState(ids.toSet(), C, shares)
        afterState()
        net.host(sk, pub) { from, body, _ -> handle(from, body) }
    }
    /** What other members send this device directly (§6.7.6: live devices get the list and their delivery). */
    private fun handle(from: String, body: JSONObject): JSONObject? = when (body.optString("type")) {
        "change" -> { val a = body.optJSONArray("events"); if (a != null) takeChanges((0 until minOf(a.length(), CHANGES_PER_MESSAGE)).mapNotNull { a.optJSONObject(it)?.let(Event::of) }); JSONObject().put("type", "ack") }
        "join_hello" -> try { inviter?.onHello(from, body, net.now) } catch (_: KeykinException) { null }
        "delta_push" -> { body.optJSONObject("wrap")?.let { takeDelivery(it) }; applyAll(); JSONObject().put("type", "ack") }
        else -> null
    }
    private fun msg(type: String, cls: String) = JSONObject().put("v", 1).put("type", type).put("g", g).put("epoch", epochId)
        .put("id", hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })).put("cls", cls)

    /** §3.2: adopt changes one at a time in id order, refusing any that would break an invariant. Only
     *  changes of this account signed by its group key are candidates: anything else would join the set for
     *  good and cost a recompute each time (review 13 H1). */
    @Synchronized fun takeChanges(evs: List<Event>) {
        if (wiped) return
        val have = changes.map { it.id }.toHashSet()
        var cur = changes; val out = ArrayList<Event>()
        val cands = (evs.take(CHANGES_PER_MESSAGE) + refused).filter { it.id !in have }.distinctBy { it.id }.filter { Membership.parses(rec, it) }.sortedBy { it.id }
        if (cands.isEmpty()) return
        for (e in cands) {
            val t = Membership.compute(rec, cur + e)
            if (t.invariant) out += e else cur = cur + e
        }
        changes = cur; refused = out.take(REFUSED_MAX)
        recompute()
        applyAll()
        save()
    }
    private fun recompute() {
        view = Membership.compute(rec, changes)
        if (pub in view.removed) wipe()
        afterState()
    }
    /** Call `cb` when this device holds no key material any more (wiped or removed): a library stops using
     *  any key it cached, the NIP-46 home ends its grants (review 13 M6). */
    fun onGone(cb: () -> Unit): () -> Unit { gone += cb; return { gone -= cb } }
    /** A removed member destroys everything it holds (core §7.3), and its stored state says only that. */
    @Synchronized fun wipe() {
        if (wiped) return
        wiped = true; state = ShareState(emptySet(), state.C, emptyMap())
        baseDk = ""; dkSeeds.clear(); releaseSeeds.clear(); pending.clear(); kept.clear(); paperVerified.clear(); dkHistory.clear()
        notices.clear(); onSiteRequest = null; carried = JSONObject()
        for (cb in gone) try { cb() } catch (_: Exception) {}
        save()
    }
    /** A sealed delivery: "kept", "junk" (never applied: safe to ack), or "full" (no room yet: leave it at
     *  the server, whose copy is the only other one). Only the dealer's delta counts (§6.7.3); before the
     *  redeal is known, only from a current device, one per sender per redeal, bounded (review 13 M1). */
    @Synchronized fun takeDelivery(w: JSONObject): String {
        if (wiped) return "junk"
        val o = try { env.unwrap(sk, w) } catch (_: Exception) { return "junk" }
        val id = o.body.opt("redeal") as? String
        if (o.body.optString("type") != "delta" || id == null || !Regex("^[0-9a-f]{32}$").matches(id) || o.body.optJSONArray("deltas") == null) return "junk"
        val v = view; val r = v.redeals[id]?.r
        if (if (r != null) o.from != r.getString("dealer") else o.from !in v.devices || o.from in v.removed) return "junk"
        if (id in state.ids || id in v.abandoned) return "junk"
        val at = pending[id]
        if (at == null || o.from !in at) {
            if ((at?.size ?: 0) >= PENDING_PER_REDEAL || pending.values.sumOf { it.size } >= PENDING_MAX || pending.values.count { o.from in it } >= PENDING_PER_SENDER) return "full"
        }
        pending.getOrPut(id) { LinkedHashMap() }[o.from] = JSONObject(o.body.toString()).put("from", o.from).put("at", net.now)
        save()
        return "kept"
    }
    /** Apply every redeal there is a delivery for (§6.7.1), checking the rebuilt commitment each time. */
    @Synchronized fun applyAll() {
        if (wiped) return
        val backup = ints(rec.getJSONObject("seats").getJSONArray("backup"))
        // Deliveries for redeals applied or abandoned, or kept past an upload's life, go.
        val now = net.now
        pending.entries.removeIf { (id, _) -> id in state.ids || id in view.abandoned }
        for (m in pending.values) m.values.removeIf { now - it.optLong("at", now) > PENDING_TTL_S }
        pending.values.removeIf { it.isEmpty() }
        var again = true; var moved = false
        while (again) {
            again = false
            for ((id, info) in view.redeals) {
                val from = info.r.getString("dealer"); val d = pending[id]?.get(from) ?: continue
                if (Upkeep.applicable(state, info.r, view.abandoned) != null) continue
                // Any fault in a dealer's delivery drops it: it never wedges every later apply (review 13 M2).
                try {
                    Upkeep.checkDelivery(info.r, from, d, true)
                    // §6.7.1 step 0: the paper item, opened with its conversation key; a bad one is shown.
                    val pk = "${view.backup}:$id"
                    if (d.has("paper_item") && d.has("paper_ck")) {
                        val item = d.opt("paper_item") as? JSONObject; val ck = d.opt("paper_ck") as? String
                        val ok = item != null && ck != null && Upkeep.verifyPaperItem(info.r, item, d.optString("release"), ck, backup)
                        paperVerified[pk] = ok
                        if (!ok) notices += JSONObject().put("kind", "bad_paper_item").put("member", from)
                    }
                    val dl = d.getJSONArray("deltas")
                    val deltas = (0 until dl.length()).associate { dl.getJSONArray(it).let { p -> Json.long(p.get(0)) to Upkeep.scalar(p.get(1)) } }
                    if (deltas.size != dl.length()) refuse("bad_redeal", "an index twice")
                    val applied = Upkeep.apply(g, state, info.r, deltas, backup, view.abandoned)
                    state = applied.state
                    // §6.7.1 step 3: keep δ(b) and the data-key seed until the current paper's item is verified.
                    if (paperVerified[pk] != true) kept[id] = JSONObject().put("b", org.json.JSONArray(backup)).put("d", org.json.JSONArray(applied.paperValues.map(::scalarHex)))
                        .put("dk", d.optString("dk")).put("release", d.optString("release"))
                    if (d.has("release")) releaseSeeds[id] = d.getString("release")
                    d.optString("dk").takeIf { it.isNotEmpty() && it !in dkSeeds }?.let { dkSeeds += it }
                } catch (_: Exception) {
                    pending.remove(id); notices += JSONObject().put("kind", "bad_delivery").put("member", from); continue
                }
                pending.remove(id)
                afterState()
                again = true; moved = true
            }
        }
        if (moved) save()
    }
    /** The durable parts of a snapshot (TS's or ours): seeds, deliveries waiting, paper values and bits,
     *  notices, refused changes, data-key history, the members log. */
    @Synchronized private fun restore(x: JSONObject) {
        carried = JSONObject(x.toString())
        x.optJSONArray("seeds")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> releaseSeeds[p.getString(0)] = p.getString(1) } }
        x.optJSONArray("pendingDeltas")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> val b = p.getJSONObject(1)
            pending.getOrPut(b.optString("redeal")) { LinkedHashMap() }[b.optString("from")] = b } }
        x.optJSONArray("kept")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> kept[p.getString(0)] = p.getJSONObject(1) } }
        x.optJSONArray("paperVerified")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> paperVerified[p.getString(0)] = p.getBoolean(1) } }
        x.optJSONArray("notices")?.let { a -> for (k in 0 until a.length()) a.optJSONObject(k)?.let { notices += it } }
        x.optJSONArray("refused")?.let { a -> refused = (0 until minOf(a.length(), REFUSED_MAX)).mapNotNull { a.optJSONObject(it)?.let(Event::of) } }
        x.optJSONArray("dkHistory")?.let { a -> dkHistory.clear(); for (k in 0 until a.length()) dkHistory += strsOf(a.getJSONArray(k)) }
        members.load(x.optJSONObject("members"))
        afterState()
    }
    private fun afterState() {
        if (wiped) return
        if (baseDk.isNotEmpty()) { val ids = state.ids.sorted(); if (dkHistory.lastOrNull() != ids) dkHistory += ids }
        members.update(pub, view, state.ids)
    }
    /** This device's state in the TS reference's snapshot form (device/node.ts `snapshot()`); only that
     *  it was wiped, once it was. */
    @Synchronized fun snapshot(): String {
        if (wiped) return JSONObject().put("v", 1).put("wiped", true).toString()
        val x = JSONObject(carried.toString())
        val ja = { l: Collection<Any?> -> org.json.JSONArray(l) }
        x.put("v", 1).put("role", "device").put("kp", hex(sk)).put("recEv", recEv.json()).put("wiped", false)
            .put("changes", ja(changes.map { it.json() })).put("refused", ja(refused.map { it.json() }))
            .put("state", JSONObject().put("ids", ja(state.ids.sorted())).put("shares", ja(state.shares.toSortedMap().map { (i, s) -> ja(listOf(i, scalarHex(s))) })))
            .put("seeds", ja(releaseSeeds.map { (k, v) -> ja(listOf(k, v)) })).put("baseDk", baseDk).put("dkSeeds", ja(dkSeeds))
            .put("kept", ja(kept.map { (k, v) -> ja(listOf(k, v)) })).put("paperVerified", ja(paperVerified.map { (k, v) -> ja(listOf(k, v)) }))
            .put("pendingDeltas", ja(pending.flatMap { (id, m) -> m.map { (from, b) -> ja(listOf("$id:$from", b)) } })).put("notices", ja(notices.toList()))
            .put("dkHistory", ja(dkHistory.map { ja(it) })).put("members", members.dump())
        if (!x.has("name")) x.put("name", "kotlin")
        return x.toString()
    }
    private fun save() { persist?.let { p -> try { p(snapshot()) } catch (_: Exception) {} } }

    /** Catch up (§3.2, §8.2): the union of every server's change set, then every server's inbox. */
    fun fetch() {
        for (s in servers()) {
            val a = net.send(sk, s.key, msg("changes_get", "ask"))
            if (a.optString("type") == "changes") a.optJSONArray("changes")?.let { c -> takeChanges((0 until minOf(c.length(), CHANGES_PER_MESSAGE)).mapNotNull { c.optJSONObject(it)?.let(Event::of) }) }
        }
        if (wiped) return
        for (s in servers()) {
            val a = net.send(sk, s.key, msg("inbox_get", "ask"))
            if (a.optString("type") != "inbox") continue
            val items = a.optJSONArray("items") ?: continue
            val iids = org.json.JSONArray()
            for (k in 0 until items.length()) {
                val it = items.optJSONObject(k) ?: continue
                try {
                    val w = it.getJSONObject("wrap"); val o = env.unwrap(sk, w)
                    // A site's request a watching server kept goes to the NIP-46 home (review 11 M1).
                    if (o.body.optString("type") == "nip46" && o.from == s.key) o.body.optJSONObject("event")?.let { e -> onSiteRequest?.invoke(e) }
                    // A delivery with no room yet stays at the server (review 13 M1).
                    else if (takeDelivery(w) == "full") continue
                } catch (_: Exception) { /* one bad item never wedges the rest */ }
                iids.put(it.opt("iid"))
            }
            net.send(sk, s.key, msg("inbox_ack", "ask").put("iids", iids))
        }
        applyAll()
    }

    /** This device's lock (§6.1), if it has one: what approves its lists. */
    @Volatile var lock: Lock? = null
    fun approveLock(list: JSONArray, expiry: Long = net.now + 3600): JSONObject = Approve.lock(g, epochId, list, expiry, pub, lock ?: refuse("no_lock", "this device has no lock"))

    /** Make, co-sign and deliver a list (§6.7.6), as TS `submit`: one approval; for a redeal, this device
     *  deals it and uploads every recipient's delivery to the seat servers; one server co-signs every event of
     *  the list in one request (§6.7.10); the list goes to every server and the live devices; then this device
     *  applies its own delta and destroys the rest. `list` names the redeal as `{redeal: {dealer: <this key>}}`. */
    fun submit(list: JSONArray, approval: JSONObject): List<JSONObject> {
        if (wiped) refuse("wiped")
        val v = view; val st = state
        val ph = Approvals.placeholder(list)
        val backupSeat = ints(rec.getJSONObject("seats").getJSONArray("backup"))
        val post = Deal.postListView(v, list)
        var dealt: Dealt? = null
        val full = JSONArray()
        val wraps = HashMap<String, JSONObject>()
        try {
            for (k in 0 until list.length()) {
                val c = list.getJSONObject(k)
                if (!c.has("redeal")) { full.put(c); continue }
                if (c.getJSONObject("redeal").optString("dealer") != pub) refuse("not_dealer", "this device deals the list's redeal")
                val dl = Deal.deal(g, sk, st.ids, post.mapValues { it.value.shares }, Deal.postListBackup(v, list), backupSeat).also { dealt = it }
                val id = dl.redeal.getString("id")
                val items = JSONArray()
                for (x in post.values) {
                    val body = JSONObject().put("type", "delta").put("redeal", id).put("deltas", JSONArray(dl.deltas[x.key]!!.toSortedMap().map { (i, d) -> JSONArray(listOf(i, scalarHex(d))) }))
                    if (x.kind != "helper") body.put("release", dl.releaseSeed)
                    if (x.kind == "device") body.put("dk", dl.dkSeed).put("paper_ck", dl.paperCk).put("paper_item", dl.paperItem)
                    // The dealer's own delivery too: the co-signer wants one for every recipient (§6.7.3).
                    if (x.key == pub) synchronized(this) { pending.getOrPut(id) { LinkedHashMap() }[pub] = JSONObject(body.toString()).put("from", pub).put("at", net.now) }
                    val w = env.wrap(sk, x.key, body, net.now)
                    wraps[x.key] = w
                    items.put(JSONObject().put("type", "delta").put("to", x.key).put("release", x.kind != "helper").put("wrap", w))
                }
                val up = msg("upload", "member").put("list", ph).put("approval", approval).put("redeal", id).put("items", items).put("paper_item", dl.paperItem)
                for (s in post.values.filter { it.kind == "server" }) net.send(sk, s.key, JSONObject(up.toString()))
                full.put(JSONObject().put("redeal", dl.redeal))
            }
            // Every event of the list in one request, each with its own nonces (§6.7.10, §5.2).
            val now = net.now
            val evs = (0 until full.length()).map { k -> Unsigned(g, now, KIND_CHANGE, listOf(listOf("v", "1"), listOf("epoch", epochId)),
                Jcs.of(JSONObject().put("v", 1).put("g", g).put("epoch", epochId).put("change", full.get(k)).put("list", ph).put("approval", approval))) }
            val signed = coSign(st, evs)
            // The list as one to every server, current and incoming; live devices get it and their delivery directly.
            val evArr = JSONArray(signed)
            for (t in (v.members + post.values).filter { it.kind == "server" }.map { it.key }.distinct()) net.send(sk, t, JSONObject().put("type", "change").put("events", evArr))
            for (x in post.values.filter { it.kind == "device" && it.key != pub }) {
                net.tell(sk, x.key, JSONObject().put("type", "change").put("events", evArr))
                wraps[x.key]?.let { net.tell(sk, x.key, JSONObject().put("type", "delta_push").put("wrap", it)) }
            }
            takeChanges(signed.map { Event.of(it) })
            applyAll()
            return signed
        } finally {
            dealt?.destroy()
            // Our own delta is applied by now, or never will be: it goes with the rest of δ.
            dealt?.let { d -> synchronized(this) { pending[d.redeal.getString("id")]?.remove(pub) } }
        }
    }
    /** Inviting (§4.1–§4.2): the code to show, then `addInvited` once the person typed the new device's digits. */
    @Volatile var inviter: Inviter? = null
    fun invite(relays: List<String>): String = Inviter(g, pub, net.now).also { inviter = it }.invite(relays)
    /** §4.2 steps 2–4 for the invited device: its add (with its lock, approved by this device's lock), a
     *  repair of each of its indices by this device and one server, sealed to it, and the welcome. */
    fun addInvited(): String {
        val inv = inviter ?: refuse("no_invite")
        val a = inv.accepted ?: refuse("no_hello")
        if (!inv.confirmed) refuse("not_confirmed", "the person has not typed the new device's number")
        val v = view
        val seats = rec.getJSONObject("seats")
        val taken = (v.members.flatMap { it.shares } + listOf("servers", "backup", "helper").flatMap { ints(seats.getJSONArray(it)) } +
            (0 until rec.getJSONArray("members").length()).flatMap { member(rec.getJSONArray("members").getJSONObject(it)).shares }).toSet()
        var salt = 0L
        while (true) { val idx = Codes.deviceIndices(g, epochId, a.n, salt); if (idx.toSet().size == 3 && idx.none { it in taken }) break; salt++ }
        val indices = Codes.deviceIndices(g, epochId, a.n, salt)
        val list = JSONArray().put(JSONObject().put("add", JSONObject().put("key", a.n).put("kind", "device").put("lock", a.lock ?: JSONObject.NULL).put("salt", salt)))
        submit(list, approveLock(list))
        // The repair: this device and one live server, each index sealed to the new device (§4.2 step 3).
        val st = state
        var last = "no_server"
        val sigmas = servers().firstNotNullOfOrNull { s ->
            try { indices.flatMap { i -> repair(st, listOf(Signer(pub, st.shares.keys.sorted()), Signer(s.key, s.shares)), i, a.n, "add") } }
            catch (e: KeykinException) { last = e.code; null }
        } ?: refuse(last)
        for (w in sigmas) net.publishEvent(w)
        // §4.2 step 4: the welcome, with what a device holds of the account.
        val w = msg("welcome", "member").put("record", recEv.json()).put("changes", JSONArray(changes.map { it.json() })).put("state", JSONArray(st.ids.sorted()))
            .put("base_dk", baseDk).put("dk", JSONArray(dkSeeds)).put("seeds", JSONArray(releaseSeeds.map { (k, x) -> JSONArray(listOf(k, x)) }))
        carried.opt("items")?.let { w.put("items", it) }; carried.opt("base")?.let { w.put("base", it) }
        val ack = net.send(sk, a.n, w)
        if (ack.optString("type") != "ack") refuse(ack.optString("code").ifEmpty { "welcome_failed" })
        inviter = null
        return a.n
    }
    /** One repair of `participant` by `helpers` (this device among them), sealed to `sealTo` (§4.2 step 3,
     *  §6.7.4): repair_start to each helper, the deltas exchanged, repair_finish; one sigma wrap per helper. */
    private fun repair(st: ShareState, helpers: List<Signer>, participant: Long, sealTo: String, why: String): List<JSONObject> {
        val sh = Codes.stateHash(st.ids.toList())
        val rid = hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })
        val hj = JSONArray(helpers.map { JSONObject().put("key", it.key).put("indices", JSONArray(it.indices)) })
        val all = helpers.flatMap { it.indices }
        // Our own step 1: for each of our indices, the deltas to every helper index.
        val keptMine = ArrayList<String>(); val toOthers = HashMap<String, MutableList<String>>()
        for ((i, s) in st.shares) {
            val byIndex = Frost.repairDeltas(st.C, all, i, s, participant)
            for (h in helpers) for (j in h.indices) { val d = byIndex[j] ?: refuse("repair_failed"); if (h.key == pub) keptMine += d else toOthers.getOrPut(h.key) { ArrayList() } += d }
        }
        val start = JSONObject().put("type", "repair_start").put("participant", participant).put("helpers", hj).put("state", sh).put("rid", rid).put("why", why).put("seal_to", sealTo)
        val outs = HashMap<String, JSONObject>()
        for (h in helpers.filter { it.key != pub }) {
            val a = net.send(sk, h.key, JSONObject(start.toString()))
            if (a.optString("type") != "repair_delta") refuse(a.optString("code").ifEmpty { "repair_refused" }, a.optString("detail"))
            outs[h.key] = a.optJSONObject("out") ?: refuse("repair_refused")
        }
        val wraps = ArrayList<JSONObject>()
        for (h in helpers.filter { it.key != pub }) {
            val mine = env.wrap(sk, h.key, JSONObject().put("type", "repair_delta").put("participant", participant).put("rid", rid).put("deltas", JSONArray(toOthers[h.key] ?: emptyList<String>())), net.now)
            val deltas = JSONArray().put(mine)
            for (o in helpers.filter { it.key != pub && it.key != h.key }) outs[o.key]?.optJSONObject(h.key)?.let { deltas.put(it) }
            val a = net.send(sk, h.key, JSONObject().put("type", "repair_finish").put("participant", participant).put("rid", rid).put("seal_to", sealTo).put("deltas", deltas))
            if (a.optString("type") != "repair_sigma") refuse(a.optString("code").ifEmpty { "repair_refused" })
            wraps += a.getJSONObject("wrap")
        }
        // Our own sigma, from what we kept and what every other helper sent us.
        val received = helpers.filter { it.key != pub }.flatMap { h -> outs[h.key]?.optJSONObject(pub)?.let { w -> env.unwrap(sk, w).body.getJSONArray("deltas").let { d -> (0 until d.length()).map { d.getString(it) } } } ?: refuse("repair_refused", "no deltas for us") }
        val sigma = Frost.repairSigma(keptMine + received)
        wraps += env.wrap(sk, sealTo, JSONObject().put("type", "repair_sigma").put("index", participant).put("sigma", sigma).put("state", sh), net.now)
        return wraps
    }
    /** Co-sign events with the first server that answers: one event as a plain round, a list as one call. */
    private fun coSign(st: ShareState, evs: List<Unsigned>): List<JSONObject> {
        val c = RoundContext(g, epochId, st.hash, st.C)
        var last = "no_server"; var detail: String? = null
        for (s in servers()) {
            val co = Signer(s.key, s.shares)
            if (evs.size == 1) {
                val r = OneCall(c, st.shares, co, evs[0])
                val a = net.send(sk, s.key, r.request)
                if (a.optString("type") != "partial") { r.abandon(); last = a.optString("code").ifEmpty { "no_answer" }; detail = a.optString("detail"); continue }
                try { return listOf(r.finish(a)) } catch (e: KeykinException) { last = e.code } catch (_: Exception) { last = "bad_partial" }
            } else {
                val r = ListCall(c, st.shares, co, evs)
                val a = net.send(sk, s.key, r.request)
                if (a.optString("type") != "partial") { r.abandon(); last = a.optString("code").ifEmpty { "no_answer" }; detail = a.optString("detail"); continue }
                try { return r.finish(a) } catch (e: KeykinException) { last = e.code }
            }
        }
        refuse(last, detail?.ifEmpty { null })
    }

    /** The seed of each redeal this device holds one for: a seed is known by its hash, which the redeal
     *  names (`dk`), so a stray or forged seed is never used (review 12 L4). */
    private fun seedsByRedeal(): Map<String, String> {
        val byHash = dkSeeds.associateBy { hex(sha(unhex(it))) }
        return view.redeals.mapNotNull { (id, x) -> byHash[x.r.getString("dk")]?.let { id to it } }.toMap()
    }
    private fun derive(ids: Collection<String>): ByteArray? {
        if (wiped || !Regex("^[0-9a-f]{64}$").matches(baseDk)) return null
        val seeds = seedsByRedeal(); val got = ids.map { seeds[it] ?: return null }
        return unhex(Codes.dataKey(baseDk, got))
    }
    /** The data key (core §4.5), as device/datakey.ts gives it in TS: the key new data is written under,
     *  and the state hash it names. `dk(S) = HKDF("keykin-dk/1", base ‖ seeds of S, sorted)`. */
    @Synchronized fun dataKey(): Pair<String, ByteArray> {
        val key = derive(state.ids) ?: refuse("no_data_key", if (wiped) "this device was removed or wiped" else "this device holds no data key (a seed still missing)")
        return state.hash to key
    }
    /** The key for data written under `stateHash`, if this device can tell that state; null otherwise. */
    @Synchronized fun dataKeyFor(stateHash: String): ByteArray? {
        val cands = dkHistory + listOf(state.ids.sorted(), emptyList()) + view.redeals.map { (id, x) -> (strsOf(x.r.getJSONArray("base")) + id).distinct().sorted() }
        return cands.firstOrNull { Codes.stateHash(it) == stateHash }?.let { derive(it) }
    }
    private fun strsOf(a: org.json.JSONArray) = (0 until a.length()).map { a.getString(it) }
    private fun ints(a: org.json.JSONArray) = (0 until a.length()).map { Json.long(a.get(it)) }

    /** The account's current device member keys. */
    fun memberKeys(): List<String> = view.devices.filter { it !in view.removed }.sorted()
    /** Sign `message` under a registered domain with this device's member key (MemberSig). */
    fun signAsMember(domain: String, message: ByteArray): Pair<String, String> = MemberSig.sign(Secp.Reference, sk, domain, message) to pub
    /** The seated servers, as members. */
    fun servers() = view.members.filter { it.kind == "server" }
    companion object {
        /** From a device's state as the TS reference writes it (device/node.ts `snapshot()`). */
        fun fromSnapshot(snapshot: String, net: RelayNet): Device {
            val x = Json.obj(snapshot)
            if (!Json.isInt(x.opt("v")) || Json.long(x.opt("v")) != 1L || x.optBoolean("wiped")) refuse("malformed", "not a live device snapshot")
            val recEv = Event.of(x.getJSONObject("recEv"))
            val rec = Record.check(recEv, recEv.pubkey)
            val ch = x.getJSONArray("changes"); val changes = (0 until ch.length()).map { Event.of(ch.getJSONObject(it)) }
            val st = x.getJSONObject("state"); val ids = (0 until st.getJSONArray("ids").length()).map { st.getJSONArray("ids").getString(it) }
            val sh = st.getJSONArray("shares")
            val shares = (0 until sh.length()).associate { sh.getJSONArray(it).let { p -> Json.long(p.get(0)) to BigInteger(p.getString(1), 16) } }
            val seeds = x.optJSONArray("dkSeeds")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
            return Device(unhex(x.getString("kp")), recEv, rec, changes, ids, shares, net, x.optString("baseDk"), seeds).also { it.restore(x); it.lock = SoftLock.fromStored(x.optJSONObject("lock")) }
        }
        /** Join an account by its invite code (core §4.1–§4.2): hello, nonce, the 6-digit check shown by
         *  `onCheck`, then the welcome and the sigmas, checked. */
        fun join(code: String, net: RelayNet, onCheck: (String) -> Unit, timeoutMs: Long = 120_000): Device {
            val sk = ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
            val pub = Secp.Reference.pub(sk)
            val j = Joiner(pub, null, net.now, parseCode(code))
            val welcome = java.util.concurrent.CompletableFuture<Pair<String, JSONObject>>()
            // Sigmas by (sender, index), one each and a bounded number: a stranger can't grow them (review 12 L2).
            val sigmas = java.util.concurrent.ConcurrentHashMap<String, JSONObject>()
            net.host(sk, pub) { from, body, _ ->
                when (body.optString("type")) {
                    "repair_sigma" -> {
                        val key = "$from:${body.opt("index")}"
                        if (from == j.m || sigmas.size < SIGMAS_MAX) sigmas.putIfAbsent(key, JSONObject(body.toString()).put("from", from))
                        JSONObject().put("type", "ack")
                    }
                    // Only the inviter's welcome counts: `n` is public, and a stranger's would abort the join (review 12 K1).
                    "welcome" -> if (from == j.m) { welcome.complete(from to body); JSONObject().put("type", "ack") } else null
                    else -> null
                }
            }
            val deadline = System.currentTimeMillis() + timeoutMs
            val (to, hello) = j.hello()
            val nonce = net.send(sk, to, hello)
            if (nonce.optString("type") != "join_nonce") refuse(nonce.optString("code").ifEmpty { "no_nonce" })
            j.onNonce(to, nonce)
            onCheck(j.check)
            val (from, w) = welcome.get(maxOf(1, deadline - System.currentTimeMillis()), java.util.concurrent.TimeUnit.MILLISECONDS)
            // The welcome may overtake a server's sigma on the relays: wait for it, within the bound.
            var r: Joiner.Joined
            while (true) {
                try { r = j.finish(from, w, sigmas.values.toList()); break }
                catch (e: KeykinException) { if (e.code != "sigma_missing" || System.currentTimeMillis() > deadline) throw e }
                Thread.sleep(100)
            }
            // §4.2 step 5: ack to the inviter and to every server, and destroy the sigmas.
            sigmas.clear()
            for (k in listOf(from) + r.view.members.filter { it.kind == "server" }.map { it.key }) net.tell(sk, k, JSONObject().put("type", "ack"))
            // The welcome carries the base data key and every data-key seed (core §4.2 step 4, §4.5).
            val seeds = w.optJSONArray("dk")?.let { a -> (0 until a.length()).mapNotNull { (a.opt(it) as? String)?.takeIf { s -> Regex("^[0-9a-f]{64}$").matches(s) } } } ?: emptyList()
            return Device(sk, r.recEv, r.rec, r.changes, r.ids, r.shares, net, w.optString("base_dk"), seeds)
        }
    }
    /** The x coordinate of `x·P` for a peer's x-only key (core §5.5), from one server's checked answer. */
    fun ecdhX(peer: String): ByteArray {
        var last = "no_server"
        // One state for the whole round: its hash, commitment and shares together (review 13 L3).
        val st = state; if (wiped) refuse("wiped"); val c = RoundContext(g, epochId, st.hash, st.C)
        for (s in servers()) {
            val co = Signer(s.key, s.shares)
            val req = Ecdh.request(c, st.shares.keys.sorted(), co, listOf("02$peer"))
            try { return unhex(Ecdh.finish(c, req, st.shares, co, net.send(sk, s.key, req))[0].substring(2)) } catch (e: KeykinException) { last = e.code }
        }
        refuse(last)
    }
    /** NIP-44 v2 as the account, with `peer`. */
    fun nip44(peer: String, text: String, encrypt: Boolean): String {
        val ck = hmac(utf8("nip44-v2"), ecdhX(peer))
        return if (encrypt) Nip44.encrypt(text, ck) else Nip44.decrypt(text, ck)
    }
    /** NIP-04 as the account, with `peer`: AES-256-CBC under the shared x. */
    fun nip04(peer: String, text: String, encrypt: Boolean): String {
        val key = javax.crypto.spec.SecretKeySpec(ecdhX(peer), "AES")
        val c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
        val b64 = java.util.Base64.getEncoder(); val d64 = java.util.Base64.getDecoder()
        if (encrypt) {
            val iv = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(iv))
            return b64.encodeToString(c.doFinal(utf8(text))) + "?iv=" + b64.encodeToString(iv)
        }
        val parts = text.split("?iv="); if (parts.size != 2) refuse("malformed", "nip04 payload")
        c.init(javax.crypto.Cipher.DECRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(d64.decode(parts[1])))
        return Json.utf8Strict(c.doFinal(d64.decode(parts[0])))
    }

    /** Sign an event with the first server that gives a partial. */
    fun sign(kind: Int, content: String, tags: List<List<String>> = emptyList(), createdAt: Long = net.now): JSONObject {
        var last = "no_server"
        val st = state; if (wiped) refuse("wiped"); val c = RoundContext(g, epochId, st.hash, st.C)
        for (s in servers()) {
            val r = OneCall(c, st.shares, Signer(s.key, s.shares), Unsigned(g, createdAt, kind, tags, content))
            val a = net.send(sk, s.key, r.request)
            if (a.optString("type") != "partial") { r.abandon(); last = a.optString("code").ifEmpty { "no_answer" }; continue }
            // A faulty or hostile server's bad partial counts as silence: try the next one (review 12 L1).
            try { return r.finish(a) } catch (e: KeykinException) { last = e.code } catch (e: Exception) { last = "bad_partial" }
        }
        refuse(last)
    }
}
