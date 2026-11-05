// Recovering an account with its paper alone, on a Kotlin device, over real relays (core §6.5, §4.4; 14.23), as the TS
// reference's device/recover.ts and PaperHolder:
//   0. find the account: `seated?` at the hosts the app lists (route 1), else at the hosts the signposts name (route 3,
//      per signer, its highest `n` only); a hint is believed once two of its own seated servers return the same record
//      and change set, and more than one account means the person picks;
//   1. the paper's holder asks each server for a challenge and sends `release_request {r}`; each starts its wait W;
//   2. once W has passed, the release bundles: the holder opens the backup seat's shares and the material;
//   3. a new device's add, approved by `recovery`, co-signed by the paper and two servers (TwoCall); its indices repaired
//      by the paper's seat and two servers, sealed to it; the device built from the welcome;
//   4. optionally the lost devices reported, with a redeal this device deals and the paper co-signs.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.SecureRandom

object Recover {
    /** An account the paper belongs to, believed (two of its seated servers agree), with its servers. */
    class Found(val g: String, val epochId: String, val servers: List<Pair<String, String>>, val recEv: Event, val rec: JSONObject, val changes: List<Event>, val view: MembershipView)
    private const val MAX_HINTS = 8; private const val MAX_SERVERS = 16; private const val MAX_SIGNERS = 8; private const val MAX_POST_HOSTS = 8
    private val HEX32 = Regex("^[0-9a-f]{64}$")
    private fun rid() = hex(ByteArray(16).also { SecureRandom().nextBytes(it) })
    private fun msg(type: String, g: String, epoch: String, cls: String) = JSONObject().put("v", 1).put("type", type).put("g", g).put("epoch", epoch).put("id", rid()).put("cls", cls)
    private fun count(changes: List<Event>) = changes.count { e -> try { Json.obj(e.content).optJSONObject("change")?.let { it.has("seat") || it.has("paper") } == true } catch (_: Exception) { false } }

    /** Every account found for the paper `paperSk` (each believed as `findAccount` says), and whether a signpost's
     *  servers didn't answer. `hosts`: front-door host keys from the app's server list. */
    fun findAccounts(net: RelayNet, paperSk: ByteArray, hosts: List<String>): Pair<List<Found>, Boolean> {
        val paper = Keykin.secp.pub(paperSk)
        net.host(paperSk, paper)
        val h = hex(sha(unhex(paper)))
        data class Hint(val g: String, val epoch: String, val servers: List<String>)
        fun ask(host: String): List<Hint> { try {
            val ch = net.send(paperSk, host, JSONObject().put("type", "challenge"))
            val c = ch.opt("challenge") as? String ?: return emptyList()
            val a = net.send(paperSk, host, JSONObject().put("type", "seated?").put("h", h).put("challenge", c)
                .put("sig", Keykin.secp.schnorrSign(Codes.seatedAskDigest(h, c), paperSk, ByteArray(32).also { SecureRandom().nextBytes(it) })))
            if (a.optString("type") != "seated" || a.optString("host") != host ||
                !schnorrVerify(a.optString("sig"), unhex(Codes.seatedDigest(h, unhex(c), utf8(a.getString("ct")))), host)) return emptyList()
            val x = JSONArray(Nip44.decrypt(a.getString("ct"), Nip44.conversationKey(Keykin.secp, paperSk, host)))
            (0 until minOf(x.length(), MAX_HINTS)).mapNotNull { k -> x.optJSONObject(k)?.let { e ->
                val g = e.optString("g"); val ep = e.optString("epoch"); val sv = e.optJSONArray("servers") ?: return@let null
                if (!HEX32.matches(g) || ep.isEmpty()) return@let null
                Hint(g, ep, (0 until sv.length()).mapNotNull { sv.optJSONObject(it)?.optString("key")?.takeIf(HEX32::matches) }.distinct().take(MAX_SERVERS)) } }
                .let { return it }
        } catch (_: Exception) { return emptyList() } }
        // Believed: two distinct servers return the same record and change set, both seated in the membership it gives,
        // and the paper is its backup key.
        fun confirm(hint: Hint): Found? {
            class Grp(val rec: JSONObject, val changes: JSONArray, val from: MutableSet<String>)
            val groups = LinkedHashMap<String, Grp>()
            for (key in hint.servers) try {
                val a = net.send(paperSk, key, msg("changes_get", hint.g, hint.epoch, "ask"))
                val r = a.optJSONObject("record") ?: continue; val ch = a.optJSONArray("changes") ?: continue
                if (a.optString("type") != "changes" || r.optString("pubkey") != hint.g) continue
                val k = r.optString("id") + ":" + (0 until ch.length()).map { ch.optJSONObject(it)?.optString("id") ?: "" }.sorted().joinToString(",")
                groups.getOrPut(k) { Grp(r, ch, HashSet()) }.from += key
            } catch (_: Exception) {}
            var best: Found? = null
            for (grp in groups.values) try {
                if (grp.from.size < 2) continue
                val recEv = Event.of(grp.rec); val rec = Record.check(recEv, hint.g)
                if (rec.getJSONObject("epoch").getString("id") != hint.epoch) continue
                val changes = (0 until grp.changes.length()).map { Event.of(grp.changes.getJSONObject(it)) }
                val v = Membership.compute(rec, changes)
                if (v.backup != paper) continue
                val servers = v.members.filter { it.kind == "server" && it.key !in v.removed && it.key in v.seats.values }.map { it.key to (it.host ?: "") }
                if (servers.count { it.first in grp.from } < 2) continue
                if (best == null || count(changes) > count(best.changes)) best = Found(hint.g, hint.epoch, servers, recEv, rec, changes, v)
            } catch (_: Exception) {}
            return best
        }
        val found = LinkedHashMap<String, Found>()
        fun keep(f: Found) { val o = found[f.g]; if (o == null || count(f.changes) > count(o.changes)) found[f.g] = f }
        for (host in hosts.distinct()) for (hint in ask(host)) confirm(hint)?.let(::keep)
        if (found.isNotEmpty()) return found.values.toList() to false
        // Route 3: the signposts, per signer its highest integer `n` only, never a lower one because a newer one's
        // servers didn't answer (the caller retries).
        val evs = try { net.query(JSONObject().put("kinds", JSONArray(listOf(30078))).put("#d", JSONArray(listOf(Codes.signpostD(paper)))), 4000) } catch (_: Exception) { emptyList() }
        data class Post(val n: Long, val at: Long, val hosts: List<String>)
        val bySigner = LinkedHashMap<String, Post>()
        for (e in evs.filter { verifyEvent(it) }) try {
            val nTag = e.tag("n") ?: continue
            if (!Regex("^(0|[1-9][0-9]{0,8})$").matches(nTag)) continue
            val c = Json.obj(e.content)
            val hs = JSONArray(Nip44.decrypt(c.getString("backup"), Nip44.conversationKey(Keykin.secp, paperSk, c.getString("eph"))))
            val list = (0 until hs.length()).mapNotNull { hs.optJSONObject(it)?.optString("host")?.takeIf(HEX32::matches) }.distinct().take(MAX_POST_HOSTS)
            val o = bySigner[e.pubkey]
            if (o == null && bySigner.size >= MAX_SIGNERS) continue
            if (o == null || nTag.toLong() > o.n || (nTag.toLong() == o.n && e.createdAt > o.at)) bySigner[e.pubkey] = Post(nTag.toLong(), e.createdAt, list)
        } catch (_: Exception) {}
        var unreachable = false
        for ((signer, p) in bySigner) {
            var ok = false
            for (host in p.hosts) for (hint in ask(host)) { if (hint.g != signer) continue
                confirm(hint)?.let { f -> if (count(f.changes) >= p.n) { keep(f); ok = true } } }
            if (!ok) unreachable = true
        }
        return found.values.toList() to unreachable
    }
    /** The account the paper belongs to: one found, or `pick` (the person, by npub) among several; otherwise refused. */
    fun findAccount(net: RelayNet, paperSk: ByteArray, hosts: List<String>, pick: ((List<Found>) -> String?)? = null): Found {
        val (found, unreachable) = findAccounts(net, paperSk, hosts)
        val gs = found.map { it.g }.distinct()
        if (gs.size == 1) return found[0]
        if (gs.size > 1) pick?.invoke(found)?.let { g -> found.firstOrNull { it.g == g }?.let { return it } } ?: refuse("ambiguous", "this paper is the backup of ${gs.size} accounts: choose one")
        if (unreachable) refuse("unreachable", "the newest signpost's servers did not answer; try again later")
        refuse("no_account", "no server knows an account for this paper")
    }

    /** What the release bundles opened to (§6.5 step 4). */
    class Collected(val recEv: Event, val rec: JSONObject, val changes: List<Event>, val view: MembershipView, val waited: JSONArray, val state: Set<String>,
                    val shares: Map<Long, BigInteger>, val C: List<Pt?>, val dk: String, val dkSeeds: List<String>, val seeds: Map<String, String>, val items: List<JSONObject>, val base: JSONObject)
    /** The paper's holder (TS `PaperHolder`): the release request at each server, then the bundles opened. */
    class PaperHolder(private val net: RelayNet, private val paperSk: ByteArray, val g: String, val epochId: String) {
        val paper: String = Keykin.secp.pub(paperSk)
        val r: String = rid()
        /** What each server answered the release request: when its wait ends, or why not. */
        val started = LinkedHashMap<String, String>()
        /** The earliest end a server stated for its wait (unix s), once one has. */
        var endsBy: Long? = null; private set
        init { net.host(paperSk, paper) }
        fun start(servers: List<String>) {
            for (s in servers) try {
                val ch = net.send(paperSk, s, msg("challenge", g, epochId, "ask"))
                val c = ch.opt("challenge") as? String ?: run { started[s] = ch.optString("code").ifEmpty { "no_challenge" }; null } ?: continue
                val sig = Keykin.secp.schnorrSign(Approvals.detached("release_request", g, JSONObject().put("r", r).put("challenge", c)), paperSk, ByteArray(32).also { SecureRandom().nextBytes(it) })
                val a = net.send(paperSk, s, msg("release_request", g, epochId, "member").put("r", r).put("challenge", c).put("sig", sig))
                if (a.optString("type") == "notice") { val end = a.optLong("end"); started[s] = "waiting until $end"; if (end > 0) endsBy = minOf(endsBy ?: end, end) }
                else started[s] = a.optString("code").ifEmpty { a.optString("type").ifEmpty { "no_answer" } }
            } catch (_: Exception) { started[s] = "no_answer" }
        }
        fun collect(servers: List<String>): Collected {
            val bs = servers.mapNotNull { s -> try { net.send(paperSk, s, msg("release_request", g, epochId, "member").put("r", r)).takeIf { it.optString("type") == "release" } } catch (_: Exception) { null } }
            if (bs.size < 2) refuse("waited_missing")
            val recEv = Event.of(bs[0].getJSONObject("record")); val rec = Record.check(recEv, g)
            val changes = LinkedHashMap<String, Event>().also { m -> for (b in bs) b.optJSONArray("changes")?.let { a -> for (k in 0 until a.length()) Event.of(a.getJSONObject(k)).let { m[it.id] = it } } }.values.toList()
            val v = Membership.compute(rec, changes)
            // Each redeal's release seed is the one matching its pinned `rs`, whichever server sent it.
            val seeds = LinkedHashMap<String, String>()
            for (b in bs) { val a = b.optJSONArray("seeds") ?: continue
                for (k in 0 until a.length()) { val p = a.optJSONArray(k) ?: continue; val id = p.getString(0); val sd = p.getString(1)
                    if (id == "base" || v.redeals[id]?.r?.optString("rs") == hex(sha(unhex(sd)))) seeds[id] = sd } }
            val items = LinkedHashMap<String, JSONObject>().also { m -> for (b in bs) b.optJSONArray("items")?.let { a -> for (k in 0 until a.length()) a.getJSONObject(k).let { m[Upkeep.itemHash(it)] = it } } }.values.toList()
            val state = v.redeals.keys.filter { it in seeds && it !in v.abandoned }.toSet()
            val pc = v.papers.lastOrNull { it.key == paper }
            val pin = pc?.inner ?: rec.getString("backup")
            val baseSeed = (if (pc != null) v.redeals.entries.firstOrNull { it.value.listHash == pc.listHash }?.key?.let { seeds[it] } else seeds["base"]) ?: refuse("missing_item", "base")
            fun signedByK(x: JSONObject) = x.optString("kind") == "seeds" && x.optString("to") == paper && try { schnorrVerify(x.optString("sig"), sha(utf8(Upkeep.itemHash(x))), paper) } catch (_: Exception) { false }
            // The pin covers the base and K's seed items from one bundle whose set matches it (review 21 H1).
            val pick = bs.mapNotNull { b -> b.optJSONObject("base")?.let { base -> base to (b.optJSONArray("items")?.let { a -> (0 until a.length()).map { a.getJSONObject(it) } } ?: emptyList()).filter(::signedByK) } }
                .firstOrNull { (base, its) -> Material.inner(base, its) == pin || (its.isEmpty() && Upkeep.itemHash(base) == pin) } ?: refuse("bad_material", "no bundle's base and seed items match the pin")
            val C0 = rec.getJSONArray("commitment").let { a -> (0 until a.length()).map { point(a.getString(it)) } }
            val o = Material.openMaterial(g, paperSk, pin, pick.first, baseSeed, items, seeds, pick.second, C0, v.redeals.values.map { it.r }, state)
            val waited = JSONArray().also { w -> for (b in bs) b.opt("waited")?.let { w.put(it) } }
            return Collected(recEv, rec, changes, v, waited, state, o.shares, o.C, o.dk, o.dkSeeds, seeds, items, pick.first)
        }
        /** A recovery round: the paper's seat plus two servers, two-call (§4.4). */
        fun cosign(c: Collected, evs: List<Unsigned>, two: List<Signer>, extra: JSONObject = JSONObject()): List<JSONObject> {
            val ctx = RoundContext(g, epochId, Codes.stateHash(c.state.sorted()), c.C)
            val t = TwoCall(ctx, c.shares, c.shares.keys.sorted(), two, evs)
            for (s in two) t.took(s.key, net.send(paperSk, s.key, t.commitRequest()))
            val req = t.signRequest(extra = extra)
            return t.finishAll(two.associate { it.key to net.send(paperSk, it.key, JSONObject(req.toString())) })
        }
    }

    /** Recover with the paper's 24 words onto a new device (no lock until the app gives it one): the account found from
     *  `hosts` (or its signposts), the 3-day wait at its servers (`onWaiting` hears when it should end; the call asks every
     *  `pollMs` until then, or `giveUpAt`), then the new device, and the `lost` devices reported. */
    fun recoverWithPaper(net: RelayNet, words: List<String>, hosts: List<String>, lost: List<String> = emptyList(), pollMs: Long = 60_000, giveUpAt: Long? = null,
                         pick: ((List<Found>) -> String?)? = null, onWaiting: (Long?) -> Unit = {}): Device {
        val paperSk = Backup.readBackupWords(words)
        try {
            val paper = Keykin.secp.pub(paperSk)
            val f = findAccount(net, paperSk, hosts, pick)
            val P = PaperHolder(net, paperSk, f.g, f.epochId)
            val keys = f.servers.map { it.first }
            P.start(keys)
            onWaiting(P.endsBy)
            var c: Collected
            while (true) {
                try { c = P.collect(keys); break } catch (e: KeykinException) { if (e.code != "waited_missing") throw e }
                if (giveUpAt != null && System.currentTimeMillis() > giveUpAt) refuse("waiting", "the recovery wait hasn't passed yet: ${P.started.values.joinToString("; ")}")
                Thread.sleep(pollMs)
            }
            val seated = c.view.members.filter { it.kind == "server" && it.key !in c.view.removed && it.key in c.view.seats.values }
            val two = seated.take(2).map { Signer(it.key, it.shares) }
            if (two.size < 2) refuse("no_server", "two seated servers are needed")
            // The new device's add, approved by `recovery`, co-signed by the paper and two servers.
            val dSk = ByteArray(32).also { SecureRandom().nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
            val dPub = Keykin.secp.pub(dSk)
            val seats = c.rec.getJSONObject("seats")
            fun ints(a: JSONArray) = (0 until a.length()).map { Json.long(a.get(it)) }
            val taken = (c.view.members.flatMap { it.shares } + listOf("servers", "backup", "helper").flatMap { ints(seats.getJSONArray(it)) }).toSet()
            var salt = 0L
            while (true) { val idx = Codes.deviceIndices(f.g, f.epochId, dPub, salt); if (idx.toSet().size == 3 && idx.none { it in taken }) break; salt++ }
            val add = JSONArray().put(JSONObject().put("add", JSONObject().put("key", dPub).put("kind", "device").put("lock", JSONObject.NULL).put("salt", salt)))
            val ph = Approvals.placeholder(add)
            val rr = JSONObject().put("r", P.r)
            val ap = Approve.recovery(f.g, ph, paperSk, rr, c.waited)
            val ev = Unsigned(f.g, net.now, 24302, listOf(listOf("v", "1"), listOf("epoch", f.epochId)),
                Jcs.of(JSONObject().put("v", 1).put("g", f.g).put("epoch", f.epochId).put("change", add.getJSONObject(0)).put("list", ph).put("approval", ap)))
            val addEv = P.cosign(c, listOf(ev), two).single()
            for (s in seated) try { net.send(paperSk, s.key, JSONObject().put("type", "change").put("events", JSONArray().put(addEv)).put("id", rid())) } catch (_: Exception) {}
            // Its indices repaired by the paper's seat and two servers, sealed to it (§4.4).
            val changes = c.changes + Event.of(addEv)
            val view2 = Membership.compute(c.rec, changes)
            val mine = view2.members.firstOrNull { it.key == dPub }?.shares ?: refuse("no_add")
            val env = Envelope()
            val st = ShareState(c.state, c.C, c.shares)
            val helpers = listOf(Signer(paper, c.shares.keys.sorted())) + two
            val sigmas = mine.flatMap { i -> Repair.run(net, env, paperSk, st, helpers, i, dPub, "add").map { w -> env.unwrap(dSk, w).let { o -> JSONObject(o.body.toString()).put("from", o.from) } } }
            val j = Joiner(dPub, null, net.now, Code("join", f.g, paper, null, "00".repeat(16), net.now + 600, emptyList()))
                .finish(paper, JSONObject().put("record", c.recEv.json()).put("changes", JSONArray(changes.map { it.json() })).put("state", JSONArray(c.state.sorted())), sigmas, recovery = paper)
            val d = Device(dSk, c.recEv, c.rec, changes, c.state.sorted(), j.shares, net, c.dk, c.dkSeeds)
            d.takeWelcomeExtras(JSONObject().put("seeds", JSONArray(c.seeds.map { (k, x) -> JSONArray(listOf(k, x)) })).put("items", JSONArray(c.items)).put("base", c.base))
            // The lost devices reported with a redeal this device deals, approved by `recovery`, the paper co-signing.
            val gone = lost.filter { it in d.view.devices && it !in d.view.removed && it != dPub }
            if (gone.isNotEmpty()) {
                val list = JSONArray().also { l -> gone.forEach { k -> l.put(JSONObject().put("remove", k)) }; l.put(JSONObject().put("redeal", JSONObject().put("dealer", dPub))) }
                d.submit(list, Approve.recovery(f.g, Approvals.placeholder(list), paperSk, rr, c.waited)) { evs, extra -> P.cosign(c, evs, two, extra) }
            }
            return d
        } finally { paperSk.fill(0) }
    }
}
