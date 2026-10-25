package cc.aaro.cosign.core

/**
 * Reading a paper backup back (COSIGN.md §8.3), as server/backup.ts does: with the
 * paper's key, open every piece the servers kept for it, add each share's sigmas up
 * (repair) as of the epoch the paper was made in, add every later refresh's part, and
 * check each share against the key's points now.
 *
 * [b] is what a server sends the paper's key (`backup`).
 */
object Backup {
    fun restore(paperSk: String, b: Map<*, *>): List<Pair<Int, String>> {
        val open = { p: Map<*, *> ->
            Json.parse(Nip44.decrypt(p["content"] as String, Nip44.conversationKey(paperSk.hexToBytes(), p["from"] as String))) as Map<*, *>
        }
        val group = b["group"] as Map<*, *>
        val sigmas = (b["pieces"] as List<*>).flatMap { (open(it as Map<*, *>)["sigmas"] as List<*>).map { s -> s as List<*> } }
        val then = Json.stringify(mapOf("groupX" to group["groupX"], "threshold" to group["threshold"],
            "members" to (b["points"] as List<*>).map { val p = it as List<*>; mapOf("idx" to p[0], "sharePub" to p[1]) }))
        val helpers = (b["helpers"] as List<*>).size
        var shares = (b["ks"] as List<*>).map { k ->
            val kk = (k as Long).toInt()
            val mine = sigmas.filter { (it[0] as Long).toInt() == kk }.map { it[2] as String }
            check(mine.size == helpers) { "pieces missing for share $kk" }
            kk to FrostNative.repairStep3(then, Json.stringify(mine), kk)
        }
        val since = (b["epoch"] as Long).toInt()
        // Only refreshes the key has reached (epochNow): a part from one that never ran would make these wrong.
        val reached = (b["epochNow"] as? Long)?.toInt() ?: Int.MAX_VALUE
        val parts = (b["parts"] as List<*>).map { it as Map<*, *> }.filter { (it["epoch"] as Long).toInt().let { e -> e > since && e <= reached } }.map { (it["epoch"] as Long).toInt() to open(it) }
        for (epoch in parts.map { it.first }.distinct().sorted()) {
            val these = parts.filter { it.first == epoch }.map { it.second }
            shares = shares.map { (i, s) ->
                val ds = these.map { p ->
                    val d = (p["deltas"] as List<*>).map { it as List<*> }.firstOrNull { (it[0] as Long).toInt() == i }?.get(1) as? String ?: error("a refresh part is missing share $i")
                    check(Refresh.checkDelta((p["commits"] as List<*>).map { it as String }, i, d)) { "a refresh part for share $i doesn't check out" }
                    d
                }
                i to Refresh.addDeltas(s, ds)
            }
        }
        val now = (group["members"] as List<*>).flatMap { m ->
            val mm = m as Map<*, *>
            (mm["shares"] as? List<*>)?.map { val p = it as Map<*, *>; (p["idx"] as Long).toInt() to p["sharePub"] as String } ?: listOf((mm["idx"] as Long).toInt() to mm["sharePub"] as String)
        }.toMap()
        for ((i, s) in shares) check(Frost.sharePub(s) == now[i]) { "share $i doesn't match the key as it is now" }
        return shares
    }
}
