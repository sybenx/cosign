package cc.aaro.cosign.core

/**
 * Making a key with nobody ever holding it (DKG), for a weighted group: this phone runs 3
 * of the shares, each server 1, and it takes the threshold (4) to sign. The same steps
 * as the servers' dkg.ts: part-1 packages to everyone, part-2 packages to each share's
 * holder, re-sent on every [tick] until done, since relays drop things.
 *
 * [plan] is the server's: `{"session", "threshold", "holders": [{"idx", "pk"}, …]}`.
 */
class Dkg(plan: Map<*, *>, private val me: String, private val send: (String, Map<String, Any?>) -> Unit, private val onDone: (Result) -> Unit) {
    data class Result(val groupX: String, val shares: List<Pair<Int, String>>, val members: List<Pair<Int, String>>)

    val session = plan["session"] as String
    private val threshold = (plan["threshold"] as Long).toInt()
    private val holders = (plan["holders"] as List<*>).map { val h = it as Map<*, *>; (h["idx"] as Long).toInt() to h["pk"] as String }
    private val all = holders.map { it.first }
    val mine = holders.filter { it.second == me }.map { it.first }
    var done: Result? = null; private set

    private val secrets1 = HashMap<Int, String>()
    private val packages1 = HashMap<Int, String>()   // everyone's, ours included
    private val secrets2 = HashMap<Int, String>()
    private val outgoing2 = HashMap<String, MutableList<List<Any>>>() // holder pk → [from, to, package]
    private val incoming2 = HashMap<Int, HashMap<Int, String>>()      // our idx → from idx → package

    init {
        require(mine.isNotEmpty()) { "this phone isn't in the plan" }
        for (idx in mine) {
            val r = Json.parse(FrostNative.dkgPart1(idx, all.size, threshold)) as Map<*, *>
            secrets1[idx] = r["secret"] as String
            packages1[idx] = r["package"] as String
        }
    }

    private fun others() = holders.map { it.second }.distinct().filter { it != me }
    private fun holderOf(idx: Int) = holders.first { it.first == idx }.second

    /** Send what we have. Call now and every few seconds until a little after [done]: someone may still be waiting for ours. */
    @Synchronized fun tick() {
        val ours = mine.map { listOf(it, packages1[it]!!) }
        for (pk in others()) {
            send(pk, mapOf("type" to "dkg1", "session" to session, "packages" to ours))
            outgoing2[pk]?.let { send(pk, mapOf("type" to "dkg2", "session" to session, "packages" to it)) }
        }
    }

    /** A dkg1 or dkg2 message from another holder. */
    @Synchronized fun take(msg: Map<*, *>, fromPk: String) {
        if (msg["session"] != session || done != null) return
        val theirs = holders.filter { it.second == fromPk }.map { it.first }.toSet()
        val packages = msg["packages"] as? List<*> ?: return
        if (msg["type"] == "dkg1") {
            for (p in packages) { val (i, pkg) = (p as List<*>).let { (it[0] as Long).toInt() to it[1].toString() }; if (i in theirs && i !in packages1) packages1[i] = pkg }
            part2()
        } else if (msg["type"] == "dkg2") {
            for (p in packages) {
                val l = p as List<*>
                val from = (l[0] as Long).toInt(); val to = (l[1] as Long).toInt()
                if (from !in theirs || to !in mine) continue
                incoming2.getOrPut(to) { HashMap() }[from] = l[2].toString()
            }
            part3()
        }
    }

    private fun round1For(idx: Int) = Json.stringify(all.filter { it != idx }.map { listOf(it, packages1[it]) })

    private fun part2() {
        if (secrets2.isNotEmpty() || packages1.size < all.size) return
        for (idx in mine) {
            val r = Json.parse(FrostNative.dkgPart2(secrets1[idx]!!, round1For(idx))) as Map<*, *>
            secrets2[idx] = r["secret"] as String
            for (p in r["packages"] as List<*>) {
                val to = ((p as List<*>)[0] as Long).toInt(); val pkg = p[1] as String
                val holder = holderOf(to)
                if (holder == me) incoming2.getOrPut(to) { HashMap() }[idx] = pkg // between our own shares: no relay needed
                else outgoing2.getOrPut(holder) { mutableListOf() }.add(listOf(idx, to, pkg))
            }
        }
        for ((pk, r2) in outgoing2) send(pk, mapOf("type" to "dkg2", "session" to session, "packages" to r2))
        part3()
    }

    private fun part3() {
        if (done != null || secrets2.isEmpty()) return
        if (!mine.all { (incoming2[it]?.size ?: 0) >= all.size - 1 }) return
        val results = mine.map { idx ->
            val r2 = Json.stringify(incoming2[idx]!!.map { (from, p) -> listOf(from, p) })
            idx to (Json.parse(FrostNative.dkgPart3(idx, secrets2[idx]!!, round1For(idx), r2)) as Map<*, *>)
        }
        // Each of our shares must have come to the same key and the same share points.
        val first = results[0].second
        check(results.all { it.second["groupX"] == first["groupX"] && Json.stringify(it.second["members"]) == Json.stringify(first["members"]) }) { "our shares disagree about the key" }
        val members = (first["members"] as List<*>).map { val m = it as Map<*, *>; (m["idx"] as Long).toInt() to m["sharePub"] as String }
        done = Result(first["groupX"] as String, results.map { it.first to it.second["share"] as String }, members)
        secrets1.clear(); secrets2.clear()
        onDone(done!!)
    }
}
