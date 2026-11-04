// FROST-secp256k1-SHA256-TR-v1 (core §1) through the same Rust crate the TypeScript uses
// (keykin/frost, built with `--features jni`). Indices are 32-byte identifiers (§3.2).
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger

object FrostNative {
    // On the JVM, the library at `keykin.frostlib`; on Android, keykin-android calls `loadLibrary` from the APK.
    init { System.getProperty("keykin.frostlib")?.let { System.load(it) } }
    fun loadLibrary(name: String) = System.loadLibrary(name)
    @JvmStatic external fun call(name: String, args: String): String
    fun call(name: String, vararg a: Any): String = call(name, JSONArray(a.map { it.toString() }).toString())
}

fun idHex(i: Long) = scalarHex(BigInteger.valueOf(i))
private fun cj(c: List<Pt?>) = JSONArray(c.map { comp(it!!) }).toString()

object Frost {
    data class Committed(val i: Long, val nonces: String, val d: String, val e: String)
    /** §5.2: hedge = SHA-256(fresh OS randomness ‖ share ‖ context). */
    fun hedge(share: BigInteger, context: ByteArray, os: ByteArray = java.security.SecureRandom().generateSeed(32)) = hex(sha(os, unhex(scalarHex(share)), context))
    fun commit(c: List<Pt?>, i: Long, share: BigInteger, hedge: String): Committed {
        val r = JSONObject(FrostNative.call("commit", cj(c), idHex(i), scalarHex(share), hedge)); val cm = r.getJSONObject("commit")
        return Committed(i, r.getString("nonces"), cm.getString("D"), cm.getString("E"))
    }
    private fun commits(cs: List<Committed>) = JSONArray(cs.map { JSONObject().put("i", idHex(it.i)).put("D", it.d).put("E", it.e) }).toString()
    fun sign(c: List<Pt?>, x: Committed, share: BigInteger, msg: String, all: List<Committed>) = FrostNative.call("sign", cj(c), idHex(x.i), scalarHex(share), x.nonces, msg, commits(all))
    fun verifyShare(c: List<Pt?>, msg: String, all: List<Committed>, i: Long, z: String) = FrostNative.call("verifyPartial", cj(c), msg, commits(all), idHex(i), z) == "true"
    fun aggregate(c: List<Pt?>, msg: String, all: List<Committed>, zs: List<Pair<Long, String>>) =
        FrostNative.call("aggregate", cj(c), msg, commits(all), JSONArray(zs.map { JSONArray(listOf(idHex(it.first), it.second)) }).toString())
    /** Repair step 1 (§4.2 step 3, §6.7.4) for one of a helper's indices: a delta to each helper index. */
    fun repairDeltas(c: List<Pt?>, helpers: List<Long>, i: Long, share: BigInteger, participant: Long): Map<Long, String> {
        val out = JSONArray(FrostNative.call("repairStep1", cj(c), JSONArray(helpers.map(::idHex)).toString(), idHex(i), scalarHex(share), idHex(participant)))
        val back = helpers.associateBy(::idHex)
        return (0 until out.length()).associate { out.getJSONArray(it).let { p -> (back[p.getString(0)] ?: refuse("repair_failed")) to p.getString(1) } }
    }
    /** Step 2: one sigma from every delta addressed to a helper's indices. (One argument goes through the
     *  vararg form: `call(name, String)` alone is the JNI entry, which takes its string as the argument list.) */
    fun repairSigma(deltas: List<String>): String = FrostNative.call("repairStep2", *arrayOf<Any>(JSONArray(deltas).toString()))
    /** A participant's share from the helpers' sigmas (core §4.2 step 5); the Rust side checks it against `C`. */
    fun repairShare(c: List<Pt?>, sigmas: List<String>, participant: Long): BigInteger = try {
        BigInteger(FrostNative.call("repairStep3", cj(c), JSONArray(sigmas).toString(), idHex(participant)), 16)
    } catch (_: Exception) { refuse("repair_failed", "the summed share misses its point") }
    /** Account admin §1.1, all participants in one process (tests). Returns g, C and every share. */
    fun dkgLocal(indices: List<Long>): Triple<String, List<Pt?>, Map<Long, BigInteger>> {
        val rnd = java.security.SecureRandom()
        val r1 = indices.associateWith { JSONObject(FrostNative.call("dkgPart1", idHex(it), indices.size, 4, hex(ByteArray(32).also(rnd::nextBytes)))) }
        fun others(i: Long) = JSONArray(r1.filterKeys { it != i }.map { (j, x) -> JSONArray(listOf(idHex(j), x.getString("package"))) }).toString()
        val r2 = indices.associateWith { JSONObject(FrostNative.call("dkgPart2", r1[it]!!.getString("secret"), others(it))) }
        fun pkgFor(i: Long) = JSONArray(r2.filterKeys { it != i }.map { (j, x) -> val ps = x.getJSONArray("packages")
            JSONArray(listOf(idHex(j), (0 until ps.length()).map { ps.getJSONArray(it) }.first { it.getString(0) == idHex(i) }.getString(1))) }).toString()
        val out = indices.associateWith { JSONObject(FrostNative.call("dkgPart3", r2[it]!!.getString("secret"), others(it), pkgFor(it))) }
        val first = out[indices[0]]!!; val g = first.getString("groupX")
        val pts = first.getJSONArray("points").let { a -> (0 until a.length()).map { a.getJSONArray(it) }.associate { BigInteger(it.getString(0), 16) to point(it.getString(1)) } }
        val ks = pts.keys.sorted().take(3)
        val C = rebuild(listOf(BigInteger.ZERO to liftXHex(g)) + ks.map { it to pts[it]!! })
        for ((i, p) in pts) require(derive(C, i) == p) { "share point off the polynomial" }
        return Triple(g, C, out.mapValues { BigInteger(it.value.getString("share"), 16) })
    }
}
