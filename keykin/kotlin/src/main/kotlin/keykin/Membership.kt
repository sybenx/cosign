// Epoch records (core §3.1, §3.4), invariants (§3.3), approvals (§6.1, §6.2) and the order-free
// membership (§3.2, §6.7.2): a port of keykin/src/record.ts, approval.ts and membership.ts.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

private fun ints(a: JSONArray) = (0 until a.length()).map { Json.long(a.get(it)) }
private fun isInt1(v: Any?, n: Long) = Json.isInt(v) && Json.long(v) == n
private val LOCK_PUB = Regex("^04[0-9a-f]{128}$"); private val HEX64 = Regex("^[0-9a-f]{64}$")
private fun isLock(l: Any?) = l is JSONObject && (l.opt("pub") as? String)?.let(LOCK_PUB::matches) == true && (l.opt("rp") as? String)?.let(HEX64::matches) == true
private fun strs(a: JSONArray?) = if (a == null) emptyList() else (0 until a.length()).map { a.getString(it) }
private fun isHex(s: Any?, n: Int) = s is String && s.length == 2 * n && s.all { it in "0123456789abcdef" }
private fun need(ok: Boolean, code: String, msg: String? = null) { if (!ok) refuse(code, msg) }

data class Member(val key: String, val kind: String, val shares: List<Long>, val lock: JSONObject?, val host: String?, val operator: String?, val raw: JSONObject)
fun member(o: JSONObject): Member {
    val key = o.opt("key") as? String ?: refuse("invariant", "member: malformed")
    val shares = o.optJSONArray("shares") ?: refuse("invariant", "member: malformed")
    if ((0 until shares.length()).any { !Json.isInt(shares.get(it)) }) refuse("invariant", "index: indices are integers")
    return Member(key, o.opt("kind") as? String ?: "", ints(shares), o.optJSONObject("lock"), o.opt("host") as? String, o.opt("operator") as? String, o)
}

object Record {
    /** §3.3 */
    fun invariants(g: String, members: List<Member>, seats: JSONObject, removed: Set<String>) {
        fun bad(rule: String, why: String): Nothing = refuse("invariant", "$rule: $why")
        val servers = ints(seats.getJSONArray("servers")); val backup = ints(seats.getJSONArray("backup")); val helper = ints(seats.getJSONArray("helper"))
        if (servers.size != 3 || servers.toSet().size != 3) bad("seats", "exactly 3 server seats")
        if (backup.size != 2) bad("seats", "the backup seat is 2 indices")
        if (helper != Codes.helperSeat(g)) bad("seats", "the helper seat is the hashed reservation")
        val seatIdx = servers + backup + helper
        if (seatIdx.toSet().size != seatIdx.size) bad("seats", "seats overlap")
        val keys = HashSet<String>(); val hosts = HashSet<String>(); val owner = HashMap<Long, String>()
        var weak = 0; var backups = 0; var helpers = 0
        for (m in members) {
            if (!keys.add(m.key)) bad("member", "a key appears twice")
            if (m.key in removed) bad("removed", "${m.key.take(8)} is removed")
            if (m.shares.size > 3) bad("I1", "more than 3 shares")
            for (i in m.shares) { if (i < 1) bad("index", "indices are integers ≥ 1"); if (owner.put(i, m.key) != null) bad("index", "index $i held twice") }
            val kind = if (m.kind in setOf("device", "helper", "server", "backup")) m.kind else "unknown"
            if (kind == "device") { if (m.shares.size != 3) bad("device", "a device holds exactly 3 shares"); if (m.shares.any { it in seatIdx }) bad("device", "a device index collides with a seat") }
            if (kind == "server" || kind == "unknown") {
                if (m.shares.size != 1 || m.shares[0] !in servers) bad("I2", "a server holds exactly one server seat")
                if (kind == "server") { if (m.host == null) bad("I2", "a server names its host"); if (!hosts.add(m.host)) bad("I2", "one host in two seats") }
            }
            if (kind == "backup") { backups++; if (m.shares.sorted() != backup.sorted()) bad("I3", "the backup holds exactly the backup seat") }
            if (kind == "helper") { helpers++; if (m.shares != helper) bad("I6", "the helper holds exactly the helper seat") }
            if (kind == "helper" || kind == "unknown") weak += m.shares.size
        }
        if (backups > 1) bad("I3", "one backup"); if (helpers > 1) bad("I5", "at most one helper")
        if (weak >= 4) bad("I5", "members with no device and no server are worth 4")
    }
    /** §3.4 */
    fun check(ev: Event, g: String): JSONObject = try { checkInner(ev, g) } catch (e: KeykinException) { throw e } catch (e: Exception) { refuse("malformed", e.message) }
    private fun checkInner(ev: Event, g: String): JSONObject {
        need(ev.kind == 30242, "not_a_record", "kind")
        need(ev.tag("d") in setOf("keykin", "cosign", "frost"), "not_a_record", "d tag")
        val c = try { Json.obj(ev.content) } catch (_: Exception) { refuse("not_a_record", "content") }
        need(c.has("v"), "not_a_record", "content")
        need(isInt1(c.opt("v"), 1), "unsupported_version")
        val n = c.optJSONObject("epoch")?.opt("n")
        need(ev.tag("v") == "1" && Json.isInt(n) && ev.tag("epoch") == Json.long(n).toString(), "bad_record", "tags disagree with the content")
        need(ev.pubkey == g && c.optString("g") == g, "wrong_group")
        need(verifyEvent(ev), "bad_signature")
        need(c.has("prev") && c.isNull("prev") && isInt1(n, 1), "bad_record", "Core 1.x has one epoch record")
        need(isHex(c.getJSONObject("epoch").opt("id"), 16), "malformed")
        need(isInt1(c.opt("t"), 4), "bad_record", "t")
        need(c.optString("role") in setOf("master", "child") && c.optString("origin") in setOf("dkg", "import"), "bad_record")
        val C = strs(c.getJSONArray("commitment")).map(::point); need(C.size == 4, "malformed")
        need(C[0] == liftXHex(g), "bad_record", "C0 is not the group point")
        val removedArr = c.optJSONArray("removed") ?: JSONArray()
        for (k in 0 until removedArr.length()) need(isHex(removedArr.opt(k), 32), "malformed", "removed key")
        val members = (0 until c.getJSONArray("members").length()).map { member(c.getJSONArray("members").getJSONObject(it)) }
        invariants(g, members, c.getJSONObject("seats"), strs(removedArr).toSet())
        val held = members.filter { it.kind == "server" }.map { it.shares[0] }.toSet()
        need(ints(c.getJSONObject("seats").getJSONArray("servers")).all { it in held }, "invariant", "every server seat is held at creation")
        need(members.any { it.kind == "backup" }, "invariant", "the paper is made at creation")
        need(members.any { it.kind == "device" }, "invariant", "a device creates the account")
        return c
    }
}

/** What every member knows about who may approve (§3.2). */
class Authority(val g: String, val epochId: String, val devices: Set<String>, val locks: Map<String, List<JSONObject>>, val backupKeys: Set<String>, val hostKeys: Set<String>, val w: Long)

object Approvals {
    private val KNOWN = setOf("add", "remove", "lock", "seat", "paper", "redeal")
    /** The change's one type key; anything else (two keys, or an unknown one) is "unknown". */
    fun type(c: JSONObject): String { val ks = c.keySet().filter { it != "to" }; return if (ks.size == 1 && ks[0] in KNOWN && (!c.has("to") || ks[0] == "remove")) ks[0] else "unknown" }
    fun placeholder(list: JSONArray): JSONArray = JSONArray((0 until list.length()).map { k ->
        val c = list.getJSONObject(k)
        when {
            c.has("redeal") -> JSONObject().put("redeal", JSONObject().put("dealer", c.getJSONObject("redeal").getString("dealer")))
            // A paper is approved without `inner` and `state`; every other field stays (§6.7.2).
            c.opt("paper") is JSONObject -> { val p = c.getJSONObject("paper"); val o = JSONObject()
                for (k in p.keySet()) if (k != "inner" && k != "state") o.put(k, p.get(k)); JSONObject().put("paper", o) }
            else -> c
        }
    })
    fun hash(list: JSONArray) = Codes.listHash(Jcs.of(placeholder(list)))
    /** §9.5's comparison form: JCS bytes. An add always carries `lock` (core 14.16). */
    fun key(c: Any?): String = Jcs.of(c)
    fun detached(type: String, g: String, body: Any) = sha(utf8("keykin-$type/1"), unhex(g), utf8(Jcs.of(body)))
    fun shape(list: JSONArray) {
        need(list.length() > 0, "bad_list", "empty")
        val types = (0 until list.length()).map { type(list.getJSONObject(it)) }
        need(types.all { it in setOf("add", "remove", "lock", "seat", "paper", "redeal") }, "bad_list", "unknown change")
        if (("add" in types || "lock" in types) && types.size != 1) refuse("bad_list", "add and lock travel alone")
        val redeals = types.count { it == "redeal" }; val needs = types.any { it in setOf("seat", "remove", "paper") }
        if (needs && redeals != 1) refuse("mandatory_redeal")
        if (!needs && "redeal" in types && types.size != 1) refuse("bad_list")
        if (types.count { it == "paper" } > 1) refuse("bad_list", "one paper per list")
        val dealer = (0 until list.length()).map { list.getJSONObject(it) }.firstOrNull { it.has("redeal") }?.getJSONObject("redeal")?.getString("dealer")
        if (dealer != null && (0 until list.length()).any { list.getJSONObject(it).optString("remove") == dealer }) refuse("bad_list", "a removed device never deals the redeal")
        val self = (0 until list.length()).map { list.getJSONObject(it) }.filter { it.has("remove") && it.has("to") }
        if (self.isNotEmpty() && (self.size != 1 || types.size != 2 || "redeal" !in types)) refuse("bad_list", "a self remove is exactly [remove, redeal]")
    }
    fun allowed(list: JSONArray): Set<String> {
        val types = (0 until list.length()).map { type(list.getJSONObject(it)) }
        if (types == listOf("add")) return setOf("lock", "pair", "paper", "recovery")
        if (types == listOf("lock")) return setOf("pair", "paper", "recovery")
        if ((0 until list.length()).any { list.getJSONObject(it).has("remove") && list.getJSONObject(it).has("to") }) return setOf("self")
        return setOf("lock", "pair", "paper", "recovery")
    }
    /** §6.2: null when valid in every member's eyes, else the code. */
    fun check(a: Authority, list: JSONArray, ap: JSONObject): String? {
        val present = listOf("lock", "pair", "paper", "recovery", "self").filter { ap.has(it) }
        if (present.size != 1) return "bad_approval"
        val t = present[0]
        if (t !in allowed(list)) return "approval_not_allowed"
        val exp = ap.opt("expiry").let { if (Json.isInt(it) && Json.long(it) >= 0) Json.long(it) else -1L }
        if (t in setOf("lock", "pair", "paper") && exp < 0) return "bad_approval"
        val w = if (t in setOf("lock", "pair", "paper")) Codes.whatChange(hash(list), a.epochId, exp) else ByteArray(0)
        fun dev(k: String?) = k != null && k in a.devices
        return when (t) {
            "lock" -> { val l = ap.getJSONObject("lock"); val m = l.getString("member")
                if (!dev(m)) "approver_not_device" else { val errs = a.locks[m].orEmpty().map { checkAssertion(a.g, it.getString("pub"), it.getString("rp"), w, l.optJSONObject("assertion") ?: JSONObject()) }
                    if (errs.isEmpty()) "no_lock" else if (null in errs) null else errs[0] } }
            "pair" -> { val p = ap.getJSONArray("pair"); if (p.length() != 2) "bad_approval" else {
                val x = p.getJSONObject(0); val y = p.getJSONObject(1)
                when { !dev(x.getString("member")) || !dev(y.getString("member")) -> "approver_not_device"; x.getString("member") == y.getString("member") -> "pair_same_device"
                    else -> { val d = detached("pair", a.g, JSONObject().put("what", hex(w)).put("r", x.opt("r")))
                        if (schnorrVerify(x.getString("sig"), d, x.getString("member")) && schnorrVerify(y.getString("code_sig"), d, y.getString("member"))) null else "bad_signature" } } } }
            "paper" -> { val p = ap.getJSONObject("paper")
                when { !dev(p.getString("member")) -> "approver_not_device"; p.getString("backup") !in a.backupKeys -> "not_backup_key"
                    !schnorrVerify(p.getString("sig"), detached("paper", a.g, JSONObject().put("what", hex(w))), p.getString("member")) -> "bad_signature"
                    !schnorrVerify(p.getString("backup_sig"), detached("paper", a.g, JSONObject().put("list", hash(list)).put("challenge", p.getString("challenge"))), p.getString("backup")) -> "bad_signature"
                    else -> null } }
            "recovery" -> { val p = ap.getJSONObject("recovery"); val backup = p.getString("backup")
                val rr = p.optJSONObject("release_request")?.optString("r")
                when { backup !in a.backupKeys -> "not_backup_key"
                    !schnorrVerify(p.getString("backup_sig"), detached("recovery", a.g, JSONObject().put("list", hash(list))), backup) -> "bad_signature"
                    rr == null || !Regex("^[0-9a-f]{32}$").matches(rr) -> "bad_approval"
                    else -> { val wait = Codes.recoveryWaitId(backup, a.epochId, rr); val ws = p.optJSONArray("waited") ?: JSONArray()
                        val ok = (0 until ws.length()).map { ws.getJSONObject(it) }.filter { s -> s.getString("kind") == "recovery" && s.getString("wait") == wait && s.getString("server") in a.hostKeys
                            && s.getLong("end") - s.getLong("start") >= a.w && schnorrVerify(s.getString("sig"), unhex(Codes.waitedDigest(a.g, "recovery", wait, s.getLong("start"), s.getLong("end"))), s.getString("server")) }
                        if (ok.map { it.getString("server") }.toSet().size < 2) "waited_missing" else null } } }
            "self" -> { val p = ap.getJSONObject("self")
                val rm = (0 until list.length()).map { list.getJSONObject(it) }.first { it.has("remove") }
                val to = rm.getString("to"); val dealer = (0 until list.length()).map { list.getJSONObject(it) }.first { it.has("redeal") }.getJSONObject("redeal").getString("dealer")
                val d = sha(utf8("keykin-self/1"), unhex(a.g), unhex(hash(list)))
                when { p.getString("member") != rm.getString("remove") -> "bad_approval"
                    !dev(p.getString("member")) || !dev(to) || p.getString("member") == to -> "approver_not_device"
                    !schnorrVerify(p.getString("sig"), d, p.getString("member")) || !schnorrVerify(p.getString("app_sig"), d, to) -> "bad_signature"
                    dealer != to -> "self_redeal_dealer"
                    else -> null } }
            else -> "bad_approval"
        }
    }
}

/** `members`: every current member with its indices, devices with their current lock (core §3.2). */
/** A redeal of the change set (§6.7.1), with its list and the change event that carries it. */
data class RedealInfo(val r: JSONObject, val listHash: String, val changeId: String)
/** A remove (`self` when approved by the removed device itself) or an add, with who approved it. */
data class RemoveInfo(val key: String, val changeId: String, val listHash: String, val self: Boolean)
data class AddInfo(val key: String, val changeId: String, val approver: String?)
data class MembershipView(val devices: List<String>, val removed: List<String>, val seats: Map<String, String?>, val backup: String?, val refused: List<String>, val invariant: Boolean, val locks: Map<String, String?>, val members: List<Member> = emptyList(),
                          val redeals: Map<String, RedealInfo> = emptyMap(), val abandoned: Set<String> = emptySet(), val removes: List<RemoveInfo> = emptyList(), val adds: List<AddInfo> = emptyList(), val recordDevices: List<String> = emptyList())

/** §3.2, §6.7.2: the membership as a function of the record and the *set* of changes. */
object Membership {
    private class Parsed(val ev: Event, val c: JSONObject, val change: JSONObject, val type: String, val listHash: String, val list: JSONArray)

    private fun parse(rec: JSONObject, ev: Event): Parsed {
        need(ev.kind == 24302, "not_a_change", "kind")
        val c = try { Json.obj(ev.content) } catch (_: Exception) { refuse("not_a_change", "content") }
        need(c.has("v") && c.opt("change") is JSONObject, "not_a_change", "content"); need(isInt1(c.opt("v"), 1), "unsupported_version")
        need(ev.tag("v") == "1" && ev.tag("epoch") == c.optString("epoch"), "bad_change", "tags disagree with the content")
        need(c.optString("g") == rec.getString("g") && ev.pubkey == rec.getString("g"), "wrong_group")
        need(c.optString("epoch") == rec.getJSONObject("epoch").getString("id"), "wrong_epoch")
        need(verifyEvent(ev), "bad_signature")
        val list = c.optJSONArray("list") ?: refuse("bad_list", "empty"); Approvals.shape(list)
        need(Jcs.of(Approvals.placeholder(list)) == Jcs.of(list), "bad_list", "the list is carried in its placeholder form")
        val ch = c.getJSONObject("change")
        val ph = Approvals.key(Approvals.placeholder(JSONArray().put(ch)).getJSONObject(0))
        need((0 until list.length()).any { Approvals.key(list.get(it)) == ph }, "bad_list", "the change is not in its list")
        val type = Approvals.type(ch)
        need(type != "unknown", "bad_change", "exactly one change")
        fun k32(v: Any?) = need(isHex(v, 32), "malformed")
        fun h16(v: Any?) = need(isHex(v, 16), "malformed")
        val seats = rec.getJSONObject("seats")
        when (type) {
            "add" -> { val a = ch.getJSONObject("add"); k32(a.opt("key")); need(a.opt("kind") == "device", "bad_change", "a new member is always a device")
                val salt = a.opt("salt"); need(Json.isInt(salt) && Json.long(salt) in 0..0xffffffffL, "bad_change", "salt")
                need(a.has("lock") && (a.isNull("lock") || isLock(a.get("lock"))), "bad_change", "lock") }
            "remove" -> { k32(ch.opt("remove")); if (ch.has("to")) k32(ch.opt("to")) }
            "lock" -> { val l = ch.getJSONObject("lock"); k32(l.opt("member")); need(isLock(l.opt("new")), "bad_change", "lock")
                need(l.has("replaces") && (l.isNull("replaces") || l.get("replaces") is String), "bad_change", "replaces") }
            "seat" -> { val st = ch.getJSONObject("seat"); val id = st.opt("seat") as? String ?: refuse("bad_change", "no such seat")
                val m = Regex("^server:(0|[1-9][0-9]*)$").matchEntire(id); val servers = ints(seats.getJSONArray("servers"))
                need((m != null && m.groupValues[1].toLong() in servers) || id == "helper", "bad_change", "no such seat")
                if (st.has("new") && !st.isNull("new")) { val e = st.getJSONObject("new"); k32(e.opt("key"))
                    val sh = e.optJSONArray("shares")
                    if (m != null) need(e.opt("kind") == "server" && sh != null && sh.length() == 1 && Json.isInt(sh.get(0)) && Json.long(sh.get(0)) == m.groupValues[1].toLong() && e.opt("host") is String, "bad_change", "a server seat takes a server at its index")
                    else need(e.opt("kind") == "helper" && sh != null && (0 until sh.length()).all { Json.isInt(sh.get(it)) } && ints(sh) == Codes.helperSeat(rec.getString("g")), "bad_change", "the helper seat takes a helper") }
                else need(st.has("new"), "bad_change")
                need(st.has("replaces") && (st.isNull("replaces") || st.get("replaces") is String), "bad_change", "replaces") }
            "paper" -> { val p = ch.getJSONObject("paper"); k32(p.opt("key")); k32(p.opt("replaces")); k32(p.opt("inner"))
                val state = p.opt("state") as? JSONArray ?: refuse("bad_change", "a committed paper change names its state"); (0 until state.length()).forEach { h16(state.opt(it)) } }
            "redeal" -> { val r = ch.getJSONObject("redeal"); h16(r.opt("id")); for (f in listOf("dealer", "paper_to", "paper_item", "dk", "rs")) k32(r.opt(f))
                val D = r.optJSONArray("D"); need(D != null && D.length() == 3, "bad_change", "D is [D1, D2, D3]"); (0 until 3).forEach { point(D!!.getString(it)) }
                for (f in listOf("base", "abandons")) { val a = r.optJSONArray(f) ?: refuse("malformed"); (0 until a.length()).forEach { h16(a.opt(it)) } }
                val body = JSONObject(r.toMap().filterKeys { it != "sig" })
                need(schnorrVerify(r.optString("sig"), Approvals.detached("redeal", rec.getString("g"), Json.obj(Jcs.of(body))), r.getString("dealer")), "bad_signature", "dealer") }
        }
        return Parsed(ev, c, ch, type, Approvals.hash(list), list)
    }

    /** Follow a chain from its first holder along changes naming it in `replaces` (§3.2, §6.7.2). */
    private class Cand(val hash: String, val replaces: String?, val newId: String?, val value: JSONObject?, val forceVoid: Boolean = false)
    private fun follow(firstId: String?, firstVal: JSONObject?, cands: List<Cand>, same: (Cand, Cand) -> Boolean, lowest: Boolean, retired: (String) -> Unit): Triple<String?, JSONObject?, List<String>> {
        var cur = firstId; var curV = firstVal; var voided = listOf<String>(); val used = HashSet<String>()
        repeat(10_000) {
            val step = cands.filter { it.hash !in used && (if (cur != null) it.replaces == cur else if (voided.isNotEmpty()) voided.any { v -> it.replaces == "void:$v" } else it.replaces == null) }.sortedBy { it.hash }
            if (step.isEmpty()) return Triple(cur, curV, voided)
            step.forEach { used.add(it.hash) }
            val win = step[0]; val allSame = step.all { same(it, win) } && step.none { it.forceVoid }
            cur?.let(retired)
            if (allSame || lowest) { step.drop(1).forEach { if (it.newId != null && it.newId != win.newId) retired(it.newId) }; cur = win.newId; curV = win.value; voided = emptyList() }
            else { step.forEach { c -> c.newId?.let(retired) }; cur = null; curV = null; voided = step.map { it.hash } }
        }
        return Triple(cur, curV, voided)
    }

    private fun safeCheck(a: Authority, p: Parsed): String? = try { Approvals.check(a, p.list, p.c.optJSONObject("approval") ?: refuse("bad_approval")) } catch (x: KeykinException) { x.code } catch (_: Exception) { "malformed" }
    fun compute(rec: JSONObject, events: List<Event>): MembershipView {
        val g = rec.getString("g"); val epoch = rec.getJSONObject("epoch").getString("id")
        val refused = ArrayList<String>(); val parsed = ArrayList<Parsed>(); val seen = HashSet<String>()
        for (e in events) { if (!seen.add(e.id)) continue; try { parsed += parse(rec, e) } catch (x: KeykinException) { refused += x.code } catch (_: Exception) { refused += "malformed" } }
        val recMembers = (0 until rec.getJSONArray("members").length()).map { member(rec.getJSONArray("members").getJSONObject(it)) }
        val recDevices = recMembers.filter { it.kind == "device" }
        val recBackup = recMembers.firstOrNull { it.kind == "backup" }?.key
        val accepted = ArrayList<Parsed>()
        fun authority(): Authority {
            val adds = accepted.filter { it.type == "add" }.map { it.change.getJSONObject("add") }
            val devices = (recDevices.map { it.key } + adds.map { it.getString("key") }).toSet()
            val locks = HashMap<String, MutableList<JSONObject>>()
            recDevices.forEach { m -> m.lock?.let { locks.getOrPut(m.key) { mutableListOf() }.add(it) } }
            adds.forEach { a -> a.optJSONObject("lock")?.let { locks.getOrPut(a.getString("key")) { mutableListOf() }.add(it) } }
            accepted.filter { it.type == "lock" }.forEach { val l = it.change.getJSONObject("lock"); locks.getOrPut(l.getString("member")) { mutableListOf() }.add(l.getJSONObject("new")) }
            val backups = (listOfNotNull(recBackup) + accepted.filter { it.type == "paper" }.map { it.change.getJSONObject("paper").getString("key") }).toSet()
            val hosts = (recMembers.filter { it.kind == "server" }.mapNotNull { it.host } + accepted.filter { it.type == "seat" }.mapNotNull { it.change.getJSONObject("seat").optJSONObject("new")?.optString("host") }).toSet()
            return Authority(g, epoch, devices, locks, backups, hosts, 3 * 86400)
        }
        var pending = parsed.toList(); var progress = true
        while (progress && pending.isNotEmpty()) {
            progress = false; val a = authority(); val next = ArrayList<Parsed>()
            for (p in pending) if (safeCheck(a, p) == null) { accepted += p; progress = true } else next += p
            pending = next
        }
        pending.forEach { refused += safeCheck(authority(), it) ?: "malformed" }
        // A list takes effect only whole (core 14.3).
        for ((_, ps) in accepted.filter { it.list.length() > 1 }.groupBy { it.listHash }) {
            val got = ps.map { Approvals.key(Approvals.placeholder(JSONArray().put(it.change)).getJSONObject(0)) }.toSet()
            if ((0 until ps[0].list.length()).all { Approvals.key(ps[0].list.get(it)) in got }) continue
            ps.forEach { accepted.remove(it); refused += "list_incomplete" }
        }
        // A fresh redeal never abandons one that travelled with a remove (§6.7.1).
        val removeRedeals = accepted.filter { it.type == "redeal" && (0 until it.list.length()).any { k -> it.list.getJSONObject(k).has("remove") } }.map { it.change.getJSONObject("redeal").getString("id") }.toSet()
        for (p in accepted.filter { it.type == "redeal" }.toList()) { val ab = p.change.getJSONObject("redeal").getJSONArray("abandons")
            if ((0 until ab.length()).any { ab.getString(it) in removeRedeals }) { accepted.remove(p); refused += "abandons_remove_redeal" } }
        val auth = authority()
        val removed = HashSet(strs(rec.optJSONArray("removed")))
        for (p in accepted.filter { it.type == "remove" }) { val k = p.change.getString("remove"); if (k !in auth.devices) refused += "remove_not_device" else removed += k }
        // Seats, with the one-host-two-seats rule on approvals within 24 hours (core 14.10).
        val seatCh = accepted.filter { it.type == "seat" }
        val recordKeys = recMembers.map { it.key }.toSet()
        val expiryOf = { p: Parsed -> p.c.getJSONObject("approval").optLong("expiry", p.ev.createdAt) }
        val forced = HashSet<String>()
        for (x in seatCh) for (y in seatCh) {
            val hx = (x.change.getJSONObject("seat").optJSONObject("new")?.opt("host") as? String)?.ifEmpty { null }; val hy = (y.change.getJSONObject("seat").optJSONObject("new")?.opt("host") as? String)?.ifEmpty { null }
            if (x !== y && hx != null && hx == hy && x.change.getJSONObject("seat").getString("seat") != y.change.getJSONObject("seat").getString("seat") && kotlin.math.abs(expiryOf(x) - expiryOf(y)) <= 86400) forced += x.listHash
        }
        seatCh.filter { it.listHash in forced }.forEach { p -> p.change.getJSONObject("seat").optJSONObject("new")?.let { removed += it.getString("key") } }
        val servers = ints(rec.getJSONObject("seats").getJSONArray("servers"))
        val seats = LinkedHashMap<String, String?>(); val seatEntries = HashMap<String, JSONObject?>()
        for (sid in servers.map { "server:$it" } + "helper") {
            val first = if (sid == "helper") recMembers.firstOrNull { it.kind == "helper" } else recMembers.firstOrNull { it.kind == "server" && "server:${it.shares[0]}" == sid }
            val cands = seatCh.filter { it.change.getJSONObject("seat").getString("seat") == sid }.filter { val n = it.change.getJSONObject("seat").optJSONObject("new")
                n == null || !(n.getString("key") in auth.devices || n.getString("key") in recordKeys || n.getString("key") in strs(rec.optJSONArray("removed"))) }
                .map { val s = it.change.getJSONObject("seat"); Cand(it.listHash, if (s.isNull("replaces")) null else s.getString("replaces"), s.optJSONObject("new")?.getString("key"), s.optJSONObject("new"), it.listHash in forced) }
            val (cur, v, _) = follow(first?.key, first?.raw, cands, { a, b -> a.newId == b.newId || (a.value?.optString("host")?.isNotEmpty() == true && a.value.optString("host") == b.value?.optString("host")) }, false) { removed += it }
            seats[sid] = cur; seatEntries[sid] = v
        }
        val paperCands = accepted.filter { it.type == "paper" }.map { val p = it.change.getJSONObject("paper"); Cand(it.listHash, p.getString("replaces"), p.getString("key"), null) }
        val backupKey = follow(recBackup, null, paperCands, { a, b -> a.newId == b.newId }, true) { removed += it }.first
        // Adds: hashed indices; any index claimed twice voids every add claiming it.
        val claims = HashMap<Long, MutableSet<String>>()
        fun claim(i: Long, who: String) { claims.getOrPut(i) { HashSet() }.add(who) }
        recMembers.forEach { m -> m.shares.forEach { claim(it, m.key) } }
        (servers + ints(rec.getJSONObject("seats").getJSONArray("backup")) + ints(rec.getJSONObject("seats").getJSONArray("helper"))).forEach { claim(it, "seat") }
        val adds = LinkedHashMap<String, MutableList<Pair<Long, List<Long>>>>(); val addLocks = HashMap<String, String>()
        for (p in accepted.filter { it.type == "add" }) {
            val a = p.change.getJSONObject("add"); val k = a.getString("key"); val salt = a.getLong("salt"); val idx = Codes.deviceIndices(g, epoch, k, salt)
            // The same add is JCS-equal as a whole (§9.5); two different adds of one key void it.
            val same = Approvals.key(JSONObject().put("add", a)); val prev = adds.getOrPut(k) { mutableListOf() }
            if (prev.indices.none { addLocks["$k:$it"] == same }) { addLocks["$k:${prev.size}"] = same; prev += salt to idx }
            idx.forEach { claim(it, k) }
        }
        val voidAdds = HashSet<String>()
        for ((k, l) in adds) { if (l.size > 1 || k in recordKeys) { voidAdds += k; continue }
            if (l[0].second.any { (claims[it]?.size ?: 0) > 1 } || l[0].second.toSet().size != 3) voidAdds += k }
        removed += voidAdds
        // Locks: each device's lock followed along lock changes; two for one lock void it.
        val locks = HashMap<String, String?>(); val lockObjs = HashMap<String, JSONObject?>()
        val lockFirst = recDevices.associate { it.key to it.lock } + adds.filter { it.key !in voidAdds }.mapValues { (k, _) ->
            accepted.first { it.type == "add" && it.change.getJSONObject("add").getString("key") == k }.change.getJSONObject("add").optJSONObject("lock") }
        for ((k, l0) in lockFirst) {
            val cands = accepted.filter { it.type == "lock" && it.change.getJSONObject("lock").getString("member") == k }.map { val l = it.change.getJSONObject("lock")
                Cand(it.listHash, if (l.isNull("replaces")) null else l.getString("replaces"), l.getJSONObject("new").getString("pub"), l.getJSONObject("new")) }
            val f = follow(l0?.getString("pub"), l0, cands, { a, b -> a.newId == b.newId }, false) { }
            locks[k] = f.first; lockObjs[k] = if (f.first == null) null else f.second
        }
        // The membership: one key, one member.
        val entries = ArrayList<Member>()
        recDevices.filter { it.key !in removed }.forEach { entries += it }
        for ((k, l) in adds) if (k !in voidAdds && k !in removed) entries += Member(k, "device", l[0].second, null, null, null, JSONObject())
        for ((sid, k) in seats) if (k != null && k !in removed) entries += member(seatEntries[sid]!!)
        if (backupKey != null && backupKey !in removed) entries += Member(backupKey, "backup", ints(rec.getJSONObject("seats").getJSONArray("backup")), null, null, null, JSONObject())
        var invariant = false
        try { Record.invariants(g, entries, rec.getJSONObject("seats"), removed) } catch (_: KeykinException) { invariant = true }
        if (entries.map { it.key }.toSet().size != entries.size) invariant = true
        // Upkeep's inputs (§6.7.1): every redeal by id (the first carrying it), the ids abandoned, and the
        // removes and adds with who approved each (core 14.19 §5.9's members log and F5 flags).
        val redeals = LinkedHashMap<String, RedealInfo>()
        for (p in accepted.filter { it.type == "redeal" }) { val r = p.change.getJSONObject("redeal"); redeals.putIfAbsent(r.getString("id"), RedealInfo(r, p.listHash, p.ev.id)) }
        val abandoned = redeals.values.flatMap { strs(it.r.getJSONArray("abandons")) }.toSet()
        fun approver(p: Parsed): String? { val a = p.c.optJSONObject("approval") ?: return null
            return a.optJSONObject("lock")?.optString("member")?.ifEmpty { null } ?: a.optJSONArray("pair")?.optJSONObject(0)?.optString("member")?.ifEmpty { null }
                ?: a.optJSONObject("paper")?.optString("member")?.ifEmpty { null } ?: a.optJSONObject("self")?.optString("member")?.ifEmpty { null }
                ?: a.optJSONObject("recovery")?.optString("backup")?.ifEmpty { null } }
        val removes = accepted.filter { it.type == "remove" }.map { RemoveInfo(it.change.getString("remove"), it.ev.id, it.listHash, it.c.optJSONObject("approval")?.has("self") == true) }
        val addInfos = accepted.filter { it.type == "add" }.map { AddInfo(it.change.getJSONObject("add").getString("key"), it.ev.id, approver(it)) }
        return MembershipView(entries.filter { it.kind == "device" }.map { it.key }.distinct().sorted(), removed.sorted(),
            seats.mapValues { (_, v) -> if (v != null && v in removed) null else v }, backupKey, refused.sorted(), invariant, locks,
            entries.map { if (it.kind == "device") it.copy(lock = lockObjs[it.key]) else it }, redeals, abandoned, removes, addInfos, recDevices.map { it.key })
    }
}
