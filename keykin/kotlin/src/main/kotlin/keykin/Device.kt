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
/** How long a device waits on another's re-issued item before re-issuing its own (core 14.20 §6.7.6). */
private const val REISSUE_WAIT_S = 7 * 86400L

class Device(val sk: ByteArray, val recEv: Event, val rec: JSONObject, changes: List<Event>, ids: List<String>, shares: Map<Long, BigInteger>, private val net: RelayNet,
             private var baseDk: String = "", dkSeeds: List<String> = emptyList()) {
    val pub: String = Keykin.secp.pub(sk)
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
    /** §6.7.6 re-issue (core 14.20), as TS: `reissued` the hash this device re-issued per `redeal:K`; `reissueEphs`
     *  the other devices' by `from:redeal:K`; `blamed` the ones proven bad; `forceReissue` the `redeal:K`s this
     *  device re-issues despite a pending eph. */
    private val reissued = HashMap<String, String>()
    private val reissueEphs = HashMap<String, JSONObject>()
    private val blamed = HashSet<String>()
    private val forceReissue = HashSet<String>()
    private val reissuing = Any()
    /** By this device: for every applied redeal whose paper item it couldn't verify, its kept values sealed to the
     *  current K, once per redeal and K; the item to every server, `reissue_eph` to the other devices; the bit
     *  once two servers (or every live one, if fewer) confirm they hold it by hash. It waits while another
     *  device's `reissue_eph` for that redeal and K is pending. Returns how many it re-issued now. */
    fun reissueMissing(): Int = synchronized(reissuing) {
        val v = view; val K = v.backup ?: return 0
        val pc = v.papers.firstOrNull { it.key == K }
        var n = 0
        for (id in state.ids.sorted()) try {
            val (k, r) = synchronized(this) { kept[id] to v.redeals[id]?.r }
            val covered = pc != null && (id in pc.state || v.redeals.values.any { it.listHash == pc.listHash && it.r.getString("id") == id })
            if (covered || synchronized(this) { paperVerified["$K:$id"] } == true) { synchronized(this) { kept.remove(id) }; continue }
            if (k == null || r == null || k.optString("release").isEmpty()) continue
            val key = "$id:$K"
            val prev = synchronized(this) { reissued[key] }
            if (prev != null) { confirmReissue(id, K, prev); continue }
            val waiting = synchronized(this) { reissueEphs.values.any { it.optString("redeal") == id && it.optString("K") == K && net.now - it.optLong("at") <= REISSUE_WAIT_S } }
            if (waiting && synchronized(this) { key !in forceReissue }) continue
            val (item, eph) = Upkeep.reissueItem(g, r, K, k, sk)
            val hash = Upkeep.itemHash(item)
            synchronized(this) { reissued[key] = hash }; save()
            var answered = 0; var held = 0
            for (s in servers()) {
                val a = net.send(sk, s.key, msg("paper_reissue", "member").put("item", item))
                if (a.optString("type") != "error" || a.optString("code") != "unreachable") answered++
                if (a.optString("type") == "reissue_held" && a.optString("item") == hash) held++
            }
            // reissue_eph to the other devices only: an ordinary delivery, live at once (§8.2).
            for (x in v.members.filter { it.kind == "device" && it.key != pub && it.key !in v.removed }) {
                val w = env.wrap(sk, x.key, JSONObject().put("type", "reissue_eph").put("redeal", id).put("K", K).put("item", hash).put("eph", eph), net.now)
                for (s in servers()) net.send(sk, s.key, msg("deliver", "member").put("to", x.key).put("wrap", w))
                net.tell(sk, x.key, JSONObject().put("type", "delta_push").put("wrap", w))
            }
            if (held >= maxOf(1, minOf(2, answered))) synchronized(this) { paperVerified["$K:$id"] = true; kept.remove(id) }
            n++
        } catch (_: Exception) { /* one redeal's re-issue never stops the next (review 14 M2) */ }
        save()
        n
    }
    /** The re-issuer's bit, once servers confirm by hash that they hold its item. */
    private fun confirmReissue(id: String, K: String, hash: String) {
        var answered = 0; var held = 0
        for (s in servers()) {
            val a = net.send(sk, s.key, msg("reissue_get", "ask").put("by", pub).put("redeal", id).put("K", K))
            if (a.optString("code") != "unreachable") answered++
            if ((a.opt("item") as? JSONObject)?.let { Upkeep.itemHash(it) } == hash) held++
        }
        if (held >= maxOf(1, minOf(2, answered))) synchronized(this) { paperVerified["$K:$id"] = true; kept.remove(id) }
    }
    /** Another device's re-issued item (core 14.20): fetched from two live servers holding the one its `reissue_eph`
     *  names, its clear values checked, opened from the eph secret and K, compared with this device's kept values;
     *  only then the bit and the values go. Proof of a bad item: keep, re-issue once, a dismissable line naming the
     *  re-issuer, and its later reissue_eph for that redeal and K ignored. */
    fun checkReissues() {
        val v = view; val K = v.backup
        val seat = ints(rec.getJSONObject("seats").getJSONArray("backup"))
        for ((k, e) in synchronized(this) { reissueEphs.toMap() }) try {
            val id = e.getString("redeal"); val from = e.getString("from")
            if (synchronized(this) { k in blamed }) { synchronized(this) { reissueEphs.remove(k) }; continue }
            if (net.now - e.optLong("at") > REISSUE_WAIT_S) { synchronized(this) { reissueEphs.remove(k); forceReissue += "$id:${e.getString("K")}" }; continue }
            if (e.getString("K") != K) continue                        // another K: missing, until it expires
            val r = v.redeals[id]?.r ?: continue
            if (id !in state.ids) continue
            val own = synchronized(this) { kept[id] }
            if (synchronized(this) { paperVerified["$K:$id"] } == true && own == null) { synchronized(this) { reissueEphs.remove(k) }; continue }
            var held = 0; var item: JSONObject? = null
            for (s in servers()) {
                val it = net.send(sk, s.key, msg("reissue_get", "ask").put("by", from).put("redeal", id).put("K", K)).opt("item") as? JSONObject ?: continue
                if (Upkeep.itemHash(it) == e.getString("item")) { held++; item = it }
            }
            if (held < 2 || item == null) continue                     // fewer than two hold it: wait, no line
            if (Upkeep.checkReissue(g, r, item, K, { x -> x in v.devices || x in v.removed }, seat) != null) continue
            // A device that kept no values has nothing to lose: the clear δ(b)·G check is enough.
            val res = if (own == null) "ok" else Upkeep.checkItem(r, item, own.getString("release"), JSONObject().put("redeal", id).put("item", e.getString("item")).put("eph", e.getString("eph")),
                Triple(seat, own.getJSONArray("d").let { a -> (0 until a.length()).map { Upkeep.scalar(a.get(it)) } }, own.getString("dk")), seat)
            if (res == "missing") continue
            synchronized(this) {
                reissueEphs.remove(k)
                if (res == "ok") { paperVerified["$K:$id"] = true; kept.remove(id) }
                else { blamed += k; forceReissue += "$id:$K"; notices += JSONObject().put("kind", "bad_backup_piece").put("member", from).put("redeal", id).put("dismissable", true) }
            }
        } catch (_: Exception) { /* one never wedges the rest */ }
        save()
    }
    /** For tests: a re-issue item for a redeal whose values this device keeps, without sending it. */
    internal fun reissueItemFor(id: String): Pair<JSONObject, String>? = synchronized(this) { kept[id] }?.let { k -> Upkeep.reissueItem(g, view.redeals[id]!!.r, view.backup!!, k, sk) }

    /** §8.1: one push address per server and wake class, each with its own RFC 8291 keys, so addresses can't
     *  be linked across servers or accounts. By address URL: the secret, the auth secret, the class. */
    private val pushKeys = HashMap<String, JSONObject>()
    val members = Members()
    /** The account's grants (Doors §1–§2): this device's, signed by it, and every device's, for listing. */
    val grants = GrantStore(this)
    /** Doors §1's evidence for decrypts to the account itself, and the ids of the account's grant events. */
    val evidence = Evidence()
    val protectedIds: MutableSet<String> = java.util.Collections.synchronizedSet(LinkedHashSet())
    /** When this device last caught up with the servers (Doors §2: no site is answered on older news). */
    @Volatile var lastFetchAt = 0L
    private val grantPublisher = java.util.concurrent.Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "keykin-grants").also { it.isDaemon = true } }
    @Volatile private var grantPublishPending = false
    /** Publish this device's grants soon (a bind, a widen, an end), at most once a second; stored first (M6). */
    fun publishGrantsSoon() {
        save()
        if (grantPublishPending) return
        grantPublishPending = true
        grantPublisher.schedule({ grantPublishPending = false; try { publishGrants() } catch (_: Exception) {} }, 1, java.util.concurrent.TimeUnit.SECONDS)
    }
    /** Store this device's state now (after a change the app made: a grant, a sign-out). */
    fun saveNow() = save()
    /** The base data key, for the grant event's `d` (Doors §2): never leaves the device. */
    internal fun baseDataKey(): String = baseDk
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
        "pair_sign" -> { takePairSign(from, body); JSONObject().put("type", "ack") }
        "join_hello" -> try { inviter?.onHello(from, body, net.now) } catch (_: KeykinException) { null }
        // §4.3 step 4: the kept backup secret goes once a lock change committed (review 14 M4), or comes anew after an F7.
        "kept_done" -> synchronized(this) {
            val v = view; val c = body.optString("change")
            if (from !in v.devices || from in v.removed) JSONObject().put("type", "error").put("code", "not_device")
            else if (c !in v.lockChanges && v.adds.none { it.changeId == c && it.hasLock }) JSONObject().put("type", "error").put("code", "no_lock_change")
            else { carried.remove("keptSecret"); save(); JSONObject().put("type", "ack") }
        }
        "kept_new" -> synchronized(this) {
            val v = view; val secret = body.opt("secret") as? String
            if (from !in v.devices || from in v.removed) JSONObject().put("type", "error").put("code", "not_device")
            else if (secret == null || !Regex("^[0-9a-f]{64}$").matches(secret) || Keykin.secp.pub(unhex(secret)) != v.backup) JSONObject().put("type", "error").put("code", "not_current_backup")
            else { carried.put("keptSecret", secret); save(); JSONObject().put("type", "ack") }
        }
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
        notices.clear(); onSiteRequest = null; carried = JSONObject(); pushKeys.clear(); inviter = null
        reissued.clear(); reissueEphs.clear(); blamed.clear(); forceReissue.clear(); grants.clear(); evidence.clear(); synchronized(xCache) { xCache.clear() }
        for (cb in gone) try { cb() } catch (_: Exception) {}
        save()
    }
    /** A sealed delivery: "kept", "junk" (never applied: safe to ack), or "full" (no room yet: leave it at
     *  the server, whose copy is the only other one). Only the dealer's delta counts (§6.7.3); before the
     *  redeal is known, only from a current device, one per sender per redeal, bounded (review 13 M1). */
    @Synchronized fun takeDelivery(w: JSONObject): String {
        if (wiped) return "junk"
        val o = try { env.unwrap(sk, w) } catch (_: Exception) { return "junk" }
        if (o.body.optString("type") == "pair_request") { takePairRequest(o.from, o.body); return "kept" }
        if (o.body.optString("type") == "reissue_eph") {
            // §6.7.6 (core 14.20): from a current device, bound to its redeal, K and item; checked in checkReissues.
            val b = o.body; val v = view
            if (o.from !in v.devices || o.from in v.removed || o.from == pub) return "junk"
            val fields = listOf("redeal", "K", "item", "eph").map { b.opt(it) as? String }
            if (fields.any { it == null } || !Regex("^[0-9a-f]{32}$").matches(fields[0]!!)) return "junk"
            val k = "${o.from}:${fields[0]}:${fields[1]}"
            if (k in blamed || k in reissueEphs) return "junk"
            if (reissueEphs.size >= 256) return "full"
            reissueEphs[k] = JSONObject().put("redeal", fields[0]).put("K", fields[1]).put("item", fields[2]).put("eph", fields[3]).put("from", o.from).put("at", net.now)
            save()
            return "kept"
        }
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
                    val pk = "${view.backup}:$id"
                    val dl = d.getJSONArray("deltas")
                    val deltas = (0 until dl.length()).associate { dl.getJSONArray(it).let { p -> Json.long(p.get(0)) to Upkeep.scalar(p.get(1)) } }
                    if (deltas.size != dl.length()) refuse("bad_redeal", "an index twice")
                    val applied = Upkeep.apply(g, state, info.r, deltas, backup, view.abandoned)
                    // §6.7.1 step 0 (core 14.20): with δ(b1), δ(b2) worked out and before the old share goes, open the
                    // paper item from its own eph secret and compare. Missing or unbound: no bit and no line (it is
                    // re-issued). Bound but wrong: proof against the dealer, a dismissable line naming it.
                    val res = Upkeep.checkItem(info.r, d.opt("paper_item") as? JSONObject, d.getString("release"), d.opt("paper_eph") as? JSONObject,
                        Triple(backup, applied.paperValues, d.optString("dk")), backup, info.r.getString("paper_item"))
                    d.remove("paper_eph")
                    if (res == "ok") paperVerified[pk] = true
                    if (res == "bad") notices += JSONObject().put("kind", "bad_backup_piece").put("member", from).put("redeal", id).put("dismissable", true)
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
        x.optJSONArray("pushKeys")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> pushKeys[p.getString(0)] = p.getJSONObject(1) } }
        x.optJSONArray("reissued")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> reissued[p.getString(0)] = p.getString(1) } }
        x.optJSONArray("reissueEphs")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> (p.opt(1) as? JSONObject)?.let { e -> if (e.has("from")) reissueEphs[p.getString(0)] = e } } }
        x.optJSONArray("blamed")?.let { a -> for (k in 0 until a.length()) blamed += a.getString(k) }
        x.optJSONArray("forceReissue")?.let { a -> for (k in 0 until a.length()) forceReissue += a.getString(k) }
        members.load(x.optJSONObject("members"))
        grants.load(x.optJSONObject("grants"))
        evidence.load(x.optJSONObject("evidence"))
        x.optJSONArray("protectedIds")?.let { a -> for (k in 0 until a.length()) protectedIds += a.getString(k) }
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
            .put("pushKeys", ja(pushKeys.map { (u, k) -> ja(listOf(u, k)) }))
            .put("reissued", ja(reissued.map { (k, h) -> ja(listOf(k, h)) })).put("reissueEphs", ja(reissueEphs.map { (k, e) -> ja(listOf(k, e)) }))
            .put("blamed", ja(blamed.sorted())).put("forceReissue", ja(forceReissue.sorted())).put("grants", grants.dump())
            .put("evidence", evidence.dump()).put("protectedIds", ja(synchronized(protectedIds) { protectedIds.toList() }))
        if (!x.has("name")) x.put("name", "kotlin")
        return x.toString()
    }
    private fun save() { persist?.let { p -> try { p(snapshot()) } catch (_: Exception) {} } }

    /** Catch up (§3.2, §8.2): the union of every server's change set, then every server's inbox. */
    fun fetch() {
        val nipQueue = ArrayList<JSONObject>()
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
                    // Kept for after the grants' fetch, so a site signed out elsewhere is refused (review 16 M5).
                    if (o.body.optString("type") == "nip46" && o.from == s.key) o.body.optJSONObject("event")?.let { e -> nipQueue += e }
                    // A delivery with no room yet stays at the server (review 13 M1).
                    else if (takeDelivery(w) == "full") continue
                } catch (_: Exception) { /* one bad item never wedges the rest */ }
                iids.put(it.opt("iid"))
            }
            net.send(sk, s.key, msg("inbox_ack", "ask").put("iids", iids))
        }
        applyAll()
        // §6.7.6 (core 14.20): check others' re-issued items before destroying anything, then re-issue what's left.
        checkReissues()
        reissueMissing()
        // Doors §2: every device's grants, for listing and signing out; ends made elsewhere applied here.
        if (baseDk.isNotEmpty()) try {
            val (evs, answered, asked) = net.queryCounted(JSONObject().put("kinds", JSONArray(listOf(Grants.KIND))).put("authors", JSONArray(listOf(g))))
            grants.take(evs, answered, asked); for (e in evs) protectedIds += e.id; save()
        } catch (_: Exception) {}
        lastFetchAt = net.now
        for (e in nipQueue) try { onSiteRequest?.invoke(e) } catch (_: Exception) {}
    }
    /** Publish this device's grants (after a change to them: a new grant, a widen, an end). */
    fun publishGrants(): List<JSONObject> {
        // A restored copy reads its own newest event before it may publish (Doors §2, the gate).
        if (grants.goodFetchAt == 0L) fetch()
        return grants.publish(net).also { save() }
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
        Approvals.shape(list)                                // one redeal at most, and a list the servers accept (review 14 L6)
        val (v, st) = synchronized(this) { view to state }
        val ph = Approvals.placeholder(list)
        var own: Pair<String, JSONObject>? = null
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
                    if (x.kind == "device") body.put("dk", dl.dkSeed).put("paper_eph", JSONObject().put("redeal", id).put("item", Upkeep.itemHash(dl.paperItem)).put("eph", dl.paperEph))
                        .put("paper_item", dl.paperItem)
                    // Our own delivery is applied only after the co-sign, and never stored before it (review 14 M1).
                    if (x.key == pub) own = id to JSONObject(body.toString()).put("from", pub).put("at", net.now)
                    // The dealer's own delivery is uploaded too: the co-signer wants one for every recipient (§6.7.3).
                    val w = env.wrap(sk, x.key, body, net.now)
                    wraps[x.key] = w
                    val item = JSONObject().put("type", "delta").put("to", x.key).put("release", x.kind != "helper").put("wrap", w)
                    // Core 14.20: a sealed paper_eph and a dk_seed for every post-list device, declared by type.
                    if (x.kind == "device") item.put("paper_eph", true).put("dk_seed", true)
                    items.put(item)
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
            own?.let { (id, b) -> synchronized(this) { pending.getOrPut(id) { LinkedHashMap() }[pub] = b } }
            takeChanges(signed.map { Event.of(it) })
            applyAll()
            return signed
        } finally {
            dealt?.destroy(); own?.second?.let { it.remove("deltas"); it.remove("paper_eph") }
            // Our own delta is applied by now, or never will be: it goes with the rest of δ, in storage too.
            dealt?.let { d -> synchronized(this) { pending[d.redeal.getString("id")]?.remove(pub) }; save() }
        }
    }
    /** Register an address with every server for each wake class; `endpoint(server, cls)` gives the URL
     *  (on Android, a UnifiedPush endpoint per instance). Returns how many servers took them. */
    fun registerPush(endpoint: (String, String) -> String): Int {
        var n = 0
        for (s in servers()) {
            val addrs = JSONArray()
            for (cls in listOf("sign", "ask", "notice")) {
                val (ksk, kpub) = Push.newKey(); val auth = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
                val url = endpoint(s.key, cls)
                synchronized(this) { pushKeys[url] = JSONObject().put("sk", hex(ksk)).put("auth", hex(auth)).put("vapid", s.raw.optString("vapid")).put("cls", cls) }
                addrs.put(JSONObject().put("cls", cls).put("url", url).put("p256dh", b64u(kpub)).put("auth", b64u(auth)))
            }
            if (net.send(sk, s.key, msg("push_register", "member").put("addresses", addrs)).optString("type") == "ack") n++
        }
        save()
        return n
    }
    /** A push that reached `url`: decrypted, checked as from a seated server; a delivery it carries is taken
     *  at once. Returns the payload (`cls`, `id`), or null for anything not ours. The app then fetches. */
    fun onPush(url: String, body: ByteArray): JSONObject? {
        val k = synchronized(this) { pushKeys[url] } ?: return null
        val p = try { Push.read(Push.decrypt(body, unhex(k.getString("sk")), unhex(k.getString("auth"))), servers().mapNotNull { it.host }.toSet()) } catch (_: KeykinException) { return null }
        p.optJSONObject("wrap")?.let { takeDelivery(it); applyAll() }
        return p
    }

    /** A `paper` approval from the paper itself (its secret, from its 24 words), with a challenge a server bound
     *  to the backup key (§6.2). */
    fun approveWithPaper(list: JSONArray, paperSk: ByteArray): JSONObject {
        val v = view; val K = Keykin.secp.pub(paperSk)
        if (K != v.backup) refuse("not_current_backup", "this is not the current paper")
        net.host(paperSk, K)
        for (s in servers()) {
            val ch = net.send(paperSk, s.key, msg("challenge", "ask"))
            val c = ch.opt("challenge") as? String ?: continue
            return Approve.paper(g, epochId, Approvals.placeholder(list), net.now + 3600, sk, paperSk, c, s.host ?: continue)
        }
        refuse("no_server")
    }

    // --- pair (core §6.2): two devices, and the code the person types on the second -----------------------
    /** Pair requests this device was asked to approve, by id: shown with the list, approved by typing the code. */
    val pairAsks = java.util.concurrent.ConcurrentHashMap<String, JSONObject>()
    private val pairWaits = java.util.concurrent.ConcurrentHashMap<String, Pair<JSONObject, java.util.concurrent.CompletableFuture<JSONObject?>>>()
    /** Ask device `to` to approve `list` with this one: the code to show, and the approval once the person typed it there. */
    fun pairStart(list: JSONArray, to: String): Pair<String, java.util.concurrent.CompletableFuture<JSONObject?>> {
        val v = view
        if (to !in v.devices || to in v.removed || to == pub) refuse("not_device", "a pair is two current devices")
        val l = Approvals.placeholder(list); val expiry = net.now + 600
        val r = hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }); val id = hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })
        val sig = Keykin.secp.schnorrSign(Approve.pairDigest(g, epochId, l, expiry, r), sk, ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })
        val f = java.util.concurrent.CompletableFuture<JSONObject?>()
        pairWaits[id] = JSONObject().put("list", l).put("expiry", expiry).put("r", r).put("sig", sig).put("to", to) to f
        val w = env.wrap(sk, to, JSONObject().put("type", "pair_request").put("id", id).put("list", l).put("expiry", expiry).put("r", r).put("sig", sig), net.now)
        net.tell(sk, to, JSONObject().put("type", "delta_push").put("wrap", w))
        for (s in servers()) net.send(sk, s.key, msg("deliver", "member").put("to", to).put("wrap", w))
        return Codes.pairCode(g, Approvals.hash(l), r) to f
    }
    /** On the second device: the person typed `code` for request `id`. Signs only if it matches. */
    fun pairApprove(id: String, code: String): Boolean {
        val p = pairAsks[id] ?: refuse("unknown_pair")
        if (net.now > p.getLong("expiry")) { pairAsks.remove(id); refuse("expired") }
        val l = p.getJSONArray("list")
        if (!java.security.MessageDigest.isEqual(utf8(Codes.pairCode(g, Approvals.hash(l), p.getString("r"))), utf8(code))) return false
        val cs = Keykin.secp.schnorrSign(Approve.pairDigest(g, epochId, l, p.getLong("expiry"), p.getString("r")), sk, ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })
        pairAsks.remove(id)
        net.send(sk, p.getString("from"), JSONObject().put("type", "pair_sign").put("id", id).put("code_sig", cs))
        return true
    }
    private fun takePairRequest(from: String, b: JSONObject) {
        val v = view
        if (from !in v.devices || from in v.removed || from == pub) return
        val id = b.opt("id") as? String ?: return; val l = b.optJSONArray("list") ?: return; val r = b.opt("r") as? String ?: return
        val expiry = (b.opt("expiry") as? Number)?.toLong() ?: return
        if (net.now > expiry || expiry - net.now > 3600) return
        try { if ("pair" !in Approvals.allowed(l) || !schnorrVerify(b.optString("sig"), Approve.pairDigest(g, epochId, l, expiry, r), from)) return } catch (_: Exception) { return }
        if (pairAsks.size >= 16 && !pairAsks.containsKey(id)) return
        pairAsks[id] = JSONObject().put("id", id).put("from", from).put("list", l).put("expiry", expiry).put("r", r)
    }
    private fun takePairSign(from: String, b: JSONObject) {
        val id = b.opt("id") as? String ?: return
        val (w, f) = pairWaits[id] ?: return
        if (from != w.getString("to")) return
        try { if (!schnorrVerify(b.optString("code_sig"), Approve.pairDigest(g, epochId, w.getJSONArray("list"), w.getLong("expiry"), w.getString("r")), from)) return } catch (_: Exception) { return }
        pairWaits.remove(id)
        f.complete(JSONObject().put("expiry", w.getLong("expiry")).put("pair", JSONArray().put(JSONObject().put("member", pub).put("sig", w.getString("sig")).put("r", w.getString("r")))
            .put(JSONObject().put("member", from).put("code_sig", b.getString("code_sig")))))
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
        // The add, once: a retry after a failed repair or welcome finds it committed and goes on (review 14 M3).
        if (view.members.none { it.key == a.n && it.kind == "device" }) {
            val v = view
            val seats = rec.getJSONObject("seats")
            val taken = (v.members.flatMap { it.shares } + listOf("servers", "backup", "helper").flatMap { ints(seats.getJSONArray(it)) } +
                (0 until rec.getJSONArray("members").length()).flatMap { member(rec.getJSONArray("members").getJSONObject(it)).shares }).toSet()
            var salt = 0L
            while (true) { val idx = Codes.deviceIndices(g, epochId, a.n, salt); if (idx.toSet().size == 3 && idx.none { it in taken }) break; salt++ }
            val list = JSONArray().put(JSONObject().put("add", JSONObject().put("key", a.n).put("kind", "device").put("lock", a.lock ?: JSONObject.NULL).put("salt", salt)))
            submit(list, approveLock(list))
        }
        val indices = view.members.first { it.key == a.n }.shares
        // The repair: this device and one live server, each index sealed to the new device (§4.2 step 3). Any
        // fault in one server's answers moves on to the next.
        val st = state
        var last = "no_server"
        val sigmas = servers().firstNotNullOfOrNull { s ->
            try { indices.flatMap { i -> repair(st, listOf(Signer(pub, st.shares.keys.sorted()), Signer(s.key, s.shares)), i, a.n, "add") } }
            catch (e: KeykinException) { last = e.code; null } catch (_: Exception) { last = "repair_failed"; null }
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
    fun signAsMember(domain: String, message: ByteArray): Pair<String, String> = MemberSig.sign(Keykin.secp, sk, domain, message) to pub
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
            return Device(unhex(x.getString("kp")), recEv, rec, changes, ids, shares, net, x.optString("baseDk"), seeds).also { it.restore(x); if (Keykin.allowSoftLock) it.lock = SoftLock.fromStored(x.optJSONObject("lock")) }
        }
        /** Join an account by its invite code (core §4.1–§4.2): hello, nonce, the 6-digit check shown by
         *  `onCheck`, then the welcome and the sigmas, checked. */
        fun join(code: String, net: RelayNet, onCheck: (String) -> Unit, timeoutMs: Long = 120_000, lock: Lock? = null): Device {
            val sk = ByteArray(32).also { java.security.SecureRandom().nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
            val pub = Keykin.secp.pub(sk)
            // The hello names this device's lock, if it has one: the inviter's add registers it (core §4.2, §6.1).
            val j = Joiner(pub, lock?.pub, net.now, parseCode(code))
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
            return Device(sk, r.recEv, r.rec, r.changes, r.ids, r.shares, net, w.optString("base_dk"), seeds).also { it.lock = lock }
        }
    }
    /** The x coordinate of `x·P` for a peer's x-only key (core §5.5), from one server's checked answer. */
    fun ecdhX(peer: String): ByteArray {
        // A shared x is kept in memory only, at most 10 minutes (Doors §1), never stored.
        synchronized(xCache) { xCache[peer]?.let { (x, at) -> if (net.now - at <= 600 && !wiped) return x } }
        return ecdhRound(peer).also { x -> synchronized(xCache) { xCache[peer] = x to net.now; while (xCache.size > 1000) xCache.remove(xCache.keys.first()) } }
    }
    private val xCache = LinkedHashMap<String, Pair<ByteArray, Long>>()
    private fun ecdhRound(peer: String): ByteArray {
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
    /** NIP-44 v2 as the account, with `peer`. An encryption to the account's own key is recorded (Device policy §1,
     *  Doors §1's evidence): for `owner`, a grant `by:id`, or else the member app. */
    fun nip44(peer: String, text: String, encrypt: Boolean, owner: String? = null): String {
        val ck = hmac(utf8("nip44-v2"), ecdhX(peer))
        if (!encrypt) return Nip44.decrypt(text, ck)
        return Nip44.encrypt(text, ck).also { if (peer.lowercase() == g) evidence.encrypted(it, owner ?: "member") }
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
            try { return r.finish(a).also { ev -> evidence.event(kind, content); if (kind == Grants.KIND) protectedIds += ev.getString("id") } } catch (e: KeykinException) { last = e.code } catch (e: Exception) { last = "bad_partial" }
        }
        refuse(last)
    }
}
