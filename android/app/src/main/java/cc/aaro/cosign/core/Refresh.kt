package cc.aaro.cosign.core

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger

/**
 * Refresh (COSIGN.md §7.3), as server/refresh.ts does it: every remaining member moves
 * to a new epoch with the same key, so a device reported lost stops combining with
 * anything. Each dealer (this phone, when it reports one lost, and a server) picks a
 * random polynomial g of degree t-1 with g(0) = 0 and sends each remaining share g(j),
 * with commitments to g's coefficients; every member checks its deltas against them,
 * adds them, and works out every share's new point from the same commitments.
 *
 * [plan]: `{"epoch", "threshold", "dealers": [pk…], "holders": [{"idx", "pk"}…], "points": [[idx, pub]…]}`.
 */
class Refresh(val plan: Map<*, *>, private val me: String, shares: List<Pair<Int, String>>, private val send: (String, Map<String, Any?>) -> Unit, private val onDone: (Result) -> Unit, env: Env) {
    data class Result(val epoch: Int, val shares: List<Pair<Int, String>>, val points: List<Pair<Int, String>>)

    val epoch = (plan["epoch"] as Long).toInt()
    private val threshold = (plan["threshold"] as Long).toInt()
    private val dealers = (plan["dealers"] as List<*>).map { it as String }
    private val holders = (plan["holders"] as List<*>).map { val h = it as Map<*, *>; (h["idx"] as Long).toInt() to h["pk"] as String }
    private val oldPoints = (plan["points"] as List<*>).associate { val p = it as List<*>; (p[0] as Long).toInt() to p[1] as String }
    private val mine = holders.filter { it.second == me }.map { it.first }
    private val shares = shares.filter { it.first in mine }
    private val got = HashMap<String, Pair<List<String>, Map<Int, String>>>() // dealer → commitments, our deltas
    private var ours: Pair<List<String>, List<Pair<Int, String>>>? = null
    var done: Result? = null; private set

    init {
        require(this.shares.size == mine.size && this.shares.all { (i, s) -> Frost.sharePub(s) == oldPoints[i] }) { "the plan doesn't start from this phone's shares" }
        if (me in dealers) {
            // a1·x + a2·x² + …: zero at 0.
            val coeffs = List(threshold - 1) { Frost.randomScalar(env) }
            val g = { x: BigInteger -> coeffs.foldRight(BigInteger.ZERO) { c, acc -> acc.add(c).multiply(x).mod(Frost.N) } }
            val deltas = holders.map { (j, _) -> j to Frost.bytes32(g(BigInteger.valueOf(j.toLong()))).toHex() }
            ours = coeffs.map { mulG(it).toHex() } to deltas
            got[me] = ours!!.first to deltas.filter { it.first in mine }.toMap()
        }
    }

    /** Every other holder's deltas, one message each, with the commitments. */
    fun outgoing(): List<Pair<String, Map<String, Any?>>> {
        val (commits, deltas) = ours ?: return emptyList()
        return deltas.groupBy { d -> holders.first { it.first == d.first }.second }.filterKeys { it != me }
            .map { (pk, ds) -> pk to mapOf("type" to "refresh_part", "epoch" to epoch, "commits" to commits, "deltas" to ds.map { listOf(it.first, it.second) }) }
    }

    /** Call now and every few seconds until a little after [done]. */
    @Synchronized fun tick() { for ((pk, m) in outgoing()) send(pk, m); finish() }

    @Synchronized fun take(msg: Map<*, *>, fromPk: String) {
        if ((msg["epoch"] as? Long)?.toInt() != epoch || fromPk !in dealers || fromPk in got || done != null) return
        val commits = (msg["commits"] as? List<*>)?.map { it as String } ?: return
        if (commits.size != threshold - 1) return
        val deltas = HashMap<Int, String>()
        try {
            for (d in msg["deltas"] as? List<*> ?: return) {
                val l = d as List<*>; val j = (l[0] as Long).toInt(); val delta = l[1] as String
                if (j in mine && mulG(BigInteger(1, delta.hexToBytes())).contentEquals(deltaPoint(commits, j))) deltas[j] = delta
            }
        } catch (_: Exception) { return }
        if (deltas.size != mine.size) return
        got[fromPk] = commits to deltas
        finish()
    }

    private fun finish() {
        if (done != null || dealers.any { it !in got }) return
        val parts = dealers.map { got[it]!! }
        val newShares = shares.map { (i, s) -> i to Frost.bytes32(parts.fold(BigInteger(1, s.hexToBytes())) { acc, p -> acc.add(BigInteger(1, p.second[i]!!.hexToBytes())) }.mod(Frost.N)).toHex() }
        val points = holders.map { (j, _) -> j to Secp256k1.pubKeyCompress(Secp256k1.pubKeyCombine(arrayOf(Secp256k1.pubkeyParse(oldPoints[j]!!.hexToBytes()), *parts.map { deltaPoint(it.first, j) }.toTypedArray()))).toHex() }
        check(newShares.all { (i, s) -> Frost.sharePub(s) == points.first { it.first == i }.second }) { "a new share doesn't match its point" }
        done = Result(epoch, newShares, points)
        onDone(done!!)
    }

    companion object {
        fun mulG(k: BigInteger): ByteArray = Secp256k1.pubKeyCompress(Secp256k1.pubkeyCreate(Frost.bytes32(k)))

        /** g(j)·G from the commitments: Σ Ck·j^k. */
        fun deltaPoint(commits: List<String>, j: Int): ByteArray {
            var x = BigInteger.valueOf(j.toLong())
            val terms = commits.map { c -> Secp256k1.pubKeyTweakMul(Secp256k1.pubkeyParse(c.hexToBytes()), Frost.bytes32(x)).also { x = x.multiply(BigInteger.valueOf(j.toLong())).mod(Frost.N) } }
            return Secp256k1.pubKeyCompress(if (terms.size == 1) terms[0] else Secp256k1.pubKeyCombine(terms.toTypedArray()))
        }

        fun checkDelta(commits: List<String>, j: Int, delta: String) = mulG(BigInteger(1, delta.hexToBytes())).contentEquals(deltaPoint(commits, j))

        fun addDeltas(secret: String, deltas: List<String>): String =
            Frost.bytes32(deltas.fold(BigInteger(1, secret.hexToBytes())) { acc, d -> acc.add(BigInteger(1, d.hexToBytes())) }.mod(Frost.N)).toHex()
    }
}
