// A Kotlin device (step B1, growing): loaded from a device's state as the TS reference writes it
// (device/node.ts `snapshot()`), checked as core §4.4's handover step 2 says, and able to sign everyday
// events with any seated server over relays. Joins, changes and Upkeep follow.
package keykin

import org.json.JSONObject
import java.math.BigInteger

/** Sigmas a joining device keeps from senders other than its inviter (the servers are known only from the welcome). */
private const val SIGMAS_MAX = 256
/** Deliveries kept for redeals not yet known: this many redeals, this many senders each. */
private const val PENDING_MAX = 64
private const val PENDING_PER_REDEAL = 8

class Device(val sk: ByteArray, val rec: JSONObject, changes: List<Event>, ids: List<String>, shares: Map<Long, BigInteger>, private val net: RelayNet,
             private var baseDk: String = "", dkSeeds: List<String> = emptyList()) {
    val pub: String = Secp.Reference.pub(sk)
    val g: String = rec.getString("g"); val epochId: String = rec.getJSONObject("epoch").getString("id")
    private val env = Envelope()
    /** The change set in force (§3.2), and the ones refused for now (kept: a later change may admit them). */
    var changes: List<Event> = changes; private set
    private var refused: List<Event> = emptyList()
    var view: MembershipView = Membership.compute(rec, changes); private set
    var state: ShareState; private set
    val ids: Set<String> get() = state.ids
    val shares: Map<Long, BigInteger> get() = state.shares
    val ctx: RoundContext get() = RoundContext(g, epochId, state.hash, state.C)
    var wiped = false; private set
    private val dkSeeds = ArrayList(dkSeeds)
    /** Release seeds by redeal id (§7.2), and the deliveries waiting for their redeal (§6.7.1). */
    val releaseSeeds = HashMap<String, String>()
    private val pending = HashMap<String, LinkedHashMap<String, JSONObject>>()
    /** Paper values kept per redeal until the current paper's item is verified (§6.7.1 step 3). */
    val kept = HashMap<String, JSONObject>()
    val paperVerified = HashMap<String, Boolean>()
    val notices = java.util.concurrent.CopyOnWriteArrayList<JSONObject>()
    /** Every state this device has held, oldest first (core §4.5: older keys read older data). */
    private val dkHistory = ArrayList<List<String>>()
    val members = Members()
    /** A site's NIP-46 request a watching server kept for us (Doors §3.3): the home takes it. */
    var onSiteRequest: ((JSONObject) -> Unit)? = null
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
        "change" -> { val a = body.optJSONArray("events"); if (a != null) takeChanges((0 until a.length()).map { Event.of(a.getJSONObject(it)) }); JSONObject().put("type", "ack") }
        "delta_push" -> { body.optJSONObject("wrap")?.let { takeDelivery(it) }; applyAll(); JSONObject().put("type", "ack") }
        else -> null
    }
    private fun msg(type: String, cls: String) = JSONObject().put("v", 1).put("type", type).put("g", g).put("epoch", epochId)
        .put("id", hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })).put("cls", cls)

    /** §3.2: adopt changes one at a time in id order, refusing any that would break an invariant. */
    @Synchronized fun takeChanges(evs: List<Event>) {
        if (wiped) return
        val have = changes.map { it.id }.toHashSet()
        var cur = changes; val out = ArrayList<Event>()
        for (e in (evs + refused).filter { it.id !in have }.distinctBy { it.id }.sortedBy { it.id }) {
            val t = Membership.compute(rec, cur + e)
            if (t.invariant) out += e else cur = cur + e
        }
        changes = cur; refused = out
        recompute()
        applyAll()
    }
    private fun recompute() {
        view = Membership.compute(rec, changes)
        if (pub in view.removed) wipe()
        afterState()
    }
    /** A removed member destroys everything it holds (core §7.3). */
    @Synchronized fun wipe() {
        wiped = true; state = ShareState(emptySet(), state.C, emptyMap())
        baseDk = ""; dkSeeds.clear(); releaseSeeds.clear(); pending.clear(); kept.clear(); paperVerified.clear(); dkHistory.clear()
    }
    /** A sealed delivery: kept only if from the redeal's dealer (once the redeal is known). */
    @Synchronized fun takeDelivery(w: JSONObject) {
        if (wiped) return
        val o = try { env.unwrap(sk, w) } catch (_: KeykinException) { return }
        if (o.body.optString("type") != "delta") return
        val id = o.body.optString("redeal")
        val r = view.redeals[id]?.r
        // Only the dealer's delta counts (§6.7.3). Before the redeal is known, one per sender, bounded, so a
        // stranger's never stands in for the dealer's; the dealer's is picked once the redeal arrives.
        if (r != null && o.from != r.getString("dealer")) return
        if (r == null && pending[id] == null && pending.size >= PENDING_MAX) return
        val at = pending.getOrPut(id) { LinkedHashMap() }
        if (o.from in at || at.size < PENDING_PER_REDEAL) at[o.from] = o.body
    }
    /** Apply every redeal there is a delivery for (§6.7.1), checking the rebuilt commitment each time. */
    @Synchronized fun applyAll() {
        if (wiped) return
        val backup = ints(rec.getJSONObject("seats").getJSONArray("backup"))
        var again = true
        while (again) {
            again = false
            for ((id, info) in view.redeals) {
                val from = info.r.getString("dealer"); val d = pending[id]?.get(from) ?: continue
                if (Upkeep.applicable(state, info.r, view.abandoned) != null) continue
                try { Upkeep.checkDelivery(info.r, from, d, true) } catch (_: KeykinException) { pending.remove(id); notices += JSONObject().put("kind", "bad_delivery").put("member", from); continue }
                // §6.7.1 step 0: the paper item, opened with its conversation key; a bad one is shown.
                val pk = "${view.backup}:$id"
                if (d.has("paper_item") && d.has("paper_ck")) {
                    val ok = Upkeep.verifyPaperItem(info.r, d.getJSONObject("paper_item"), d.optString("release"), d.getString("paper_ck"), backup)
                    paperVerified[pk] = ok
                    if (!ok) notices += JSONObject().put("kind", "bad_paper_item").put("member", info.r.getString("dealer"))
                }
                val deltas = try { d.getJSONArray("deltas").let { a -> (0 until a.length()).associate { a.getJSONArray(it).let { p -> Json.long(p.get(0)) to BigInteger(p.getString(1), 16) } } } }
                    catch (_: Exception) { pending.remove(id); notices += JSONObject().put("kind", "bad_delivery").put("member", from); continue }
                val applied = try { Upkeep.apply(g, state, info.r, deltas, backup, view.abandoned) }
                    catch (_: KeykinException) { pending.remove(id); notices += JSONObject().put("kind", "bad_delivery").put("member", from); continue }
                state = applied.state; pending.remove(id)
                // §6.7.1 step 3: keep δ(b) and the data-key seed until the current paper's item is verified.
                if (paperVerified[pk] != true) kept[id] = JSONObject().put("b", org.json.JSONArray(backup)).put("d", org.json.JSONArray(applied.paperValues.map(::scalarHex)))
                    .put("dk", d.optString("dk")).put("release", d.optString("release"))
                if (d.has("release")) releaseSeeds[id] = d.getString("release")
                d.optString("dk").takeIf { it.isNotEmpty() && it !in dkSeeds }?.let { dkSeeds += it }
                afterState()
                again = true
            }
        }
    }
    /** The durable parts of a TS snapshot: release seeds, deliveries waiting, data-key history, the members log. */
    @Synchronized private fun restore(x: JSONObject) {
        x.optJSONArray("seeds")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> if (p.optString(0) != "base") releaseSeeds[p.getString(0)] = p.getString(1) } }
        x.optJSONArray("pendingDeltas")?.let { a -> for (k in 0 until a.length()) a.optJSONArray(k)?.let { p -> val b = p.getJSONObject(1)
            pending.getOrPut(b.optString("redeal")) { LinkedHashMap() }[b.optString("from")] = b } }
        x.optJSONArray("dkHistory")?.let { a -> dkHistory.clear(); for (k in 0 until a.length()) dkHistory += strsOf(a.getJSONArray(k)) }
        members.load(x.optJSONObject("members"))
        afterState()
    }
    private fun afterState() {
        if (!wiped && baseDk.isNotEmpty()) { val ids = state.ids.sorted(); if (dkHistory.lastOrNull() != ids) dkHistory += ids }
        members.update(pub, view, state.ids)
    }

    /** Catch up (§3.2, §8.2): the union of every server's change set, then every server's inbox. */
    fun fetch() {
        for (s in servers()) {
            val a = net.send(sk, s.key, msg("changes_get", "ask"))
            if (a.optString("type") == "changes") a.optJSONArray("changes")?.let { c -> takeChanges((0 until c.length()).map { Event.of(c.getJSONObject(it)) }) }
        }
        if (wiped) return
        for (s in servers()) {
            val a = net.send(sk, s.key, msg("inbox_get", "ask"))
            if (a.optString("type") != "inbox") continue
            val items = a.optJSONArray("items") ?: continue
            val iids = org.json.JSONArray()
            for (k in 0 until items.length()) {
                val it = items.optJSONObject(k) ?: continue
                iids.put(it.opt("iid"))
                try {
                    val w = it.getJSONObject("wrap"); val o = env.unwrap(sk, w)
                    // A site's request a watching server kept goes to the NIP-46 home (review 11 M1).
                    if (o.body.optString("type") == "nip46" && o.from == s.key) o.body.optJSONObject("event")?.let { e -> onSiteRequest?.invoke(e) }
                    else takeDelivery(w)
                } catch (_: Exception) { /* one bad item never wedges the rest */ }
            }
            net.send(sk, s.key, msg("inbox_ack", "ask").put("iids", iids))
        }
        applyAll()
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
            return Device(unhex(x.getString("kp")), rec, changes, ids, shares, net, x.optString("baseDk"), seeds).also { it.restore(x) }
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
            val seeds = w.optJSONArray("dk")?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
            return Device(sk, r.rec, r.changes, r.ids, r.shares, net, w.optString("base_dk"), seeds)
        }
    }
    /** The x coordinate of `x·P` for a peer's x-only key (core §5.5), from one server's checked answer. */
    fun ecdhX(peer: String): ByteArray {
        var last = "no_server"
        for (s in servers()) {
            val co = Signer(s.key, s.shares)
            val req = Ecdh.request(ctx, shares.keys.sorted(), co, listOf("02$peer"))
            try { return unhex(Ecdh.finish(ctx, req, shares, co, net.send(sk, s.key, req))[0].substring(2)) } catch (e: KeykinException) { last = e.code }
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
        for (s in servers()) {
            val r = OneCall(ctx, shares, Signer(s.key, s.shares), Unsigned(g, createdAt, kind, tags, content))
            val a = net.send(sk, s.key, r.request)
            if (a.optString("type") != "partial") { r.abandon(); last = a.optString("code").ifEmpty { "no_answer" }; continue }
            // A faulty or hostile server's bad partial counts as silence: try the next one (review 12 L1).
            try { return r.finish(a) } catch (e: KeykinException) { last = e.code } catch (e: Exception) { last = "bad_partial" }
        }
        refuse(last)
    }
}
