// secp256k1 for Core's non-FROST arithmetic (core §3.4 step 4, §5.5, §6.7.1), affine with BigInteger.
// Correct, not constant-time: the vectors and verification only; shares never pass through it.
package keykin

import java.math.BigInteger

val P: BigInteger = BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
val N: BigInteger = BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

data class Pt(val x: BigInteger, val y: BigInteger)
val GEN = Pt(BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16), BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16))

fun add(a: Pt?, b: Pt?): Pt? {
    if (a == null) return b; if (b == null) return a
    if (a.x == b.x && (a.y + b.y).mod(P) == BigInteger.ZERO) return null
    val l = if (a == b) BigInteger.valueOf(3) * a.x * a.x * (BigInteger.TWO * a.y).modInverse(P) else (b.y - a.y) * (b.x - a.x).modInverse(P)
    val x = (l * l - a.x - b.x).mod(P)
    return Pt(x, (l * (a.x - x) - a.y).mod(P))
}
fun mul(k: BigInteger, p: Pt? = GEN): Pt? {
    var r: Pt? = null; var q = p; var e = k.mod(N)
    while (e.signum() > 0) { if (e.testBit(0)) r = add(r, q); q = add(q, q); e = e.shiftRight(1) }
    return r
}
fun comp(p: Pt): String = (if (p.y.testBit(0)) "03" else "02") + p.x.toString(16).padStart(64, '0')
fun compBytes(p: Pt) = unhex(comp(p))
/** A 33-byte compressed point; the identity has no encoding, so it is refused. */
fun point(h: String): Pt {
    require(h.length == 66 && (h.startsWith("02") || h.startsWith("03"))) { "not a compressed point" }
    val x = BigInteger(h.substring(2), 16); require(x < P)
    val y2 = (x.pow(3) + BigInteger.valueOf(7)).mod(P)
    var y = y2.modPow((P + BigInteger.ONE).shiftRight(2), P)
    require(y.modPow(BigInteger.TWO, P) == y2) { "not on the curve" }
    if (y.testBit(0) != h.startsWith("03")) y = P - y
    return Pt(x, y)
}
fun scalarHex(k: BigInteger) = k.mod(N).toString(16).padStart(64, '0')

/** `Σ C_k·i^k`: a share point, always derived (§3.1). */
fun derive(c: List<Pt?>, i: BigInteger): Pt? { var acc: Pt? = null; var x = BigInteger.ONE; for (ck in c) { acc = add(acc, mul(x, ck)); x = (x * i).mod(N) }; return acc }
fun lagrange(i: BigInteger, xs: List<BigInteger>): BigInteger {
    require(xs.toSet().size == xs.size) { "repeated index" }
    var num = BigInteger.ONE; var den = BigInteger.ONE
    for (j in xs) if (j != i) { num = (num * j).mod(N); den = (den * (j - i)).mod(N) }
    return (num * den.modInverse(N)).mod(N)
}
/** §3.4 step 4: the degree-3 commitment from four points at distinct x. */
fun rebuild(pts: List<Pair<BigInteger, Pt>>): List<Pt?> {
    val out = arrayOfNulls<Pt>(4)
    for ((xj, yj) in pts) {
        var basis = listOf(BigInteger.ONE); var den = BigInteger.ONE
        for ((xk, _) in pts) if (xk != xj) {
            val nb = MutableList(basis.size + 1) { BigInteger.ZERO }
            basis.forEachIndexed { i, c -> nb[i] = (nb[i] - c * xk).mod(N); nb[i + 1] = (nb[i + 1] + c).mod(N) }
            basis = nb; den = (den * (xj - xk)).mod(N)
        }
        val di = den.modInverse(N)
        for (k in 0..3) out[k] = add(out[k], mul((basis[k] * di).mod(N), yj))
    }
    return out.toList()
}

/** §5.5: one weighted decryption answer's proof. */
fun verifyDleq(g: String, epoch: String, state: String, signers: List<Long>, c: List<Pt?>, q: String, i: Long, y: String, r1: String, r2: String, z: String): Boolean = try {
    val Q = point(q); val Y = point(y); val R1 = point(r1); val R2 = point(r2); val zz = BigInteger(z, 16)
    val lam = lagrange(BigInteger.valueOf(i), signers.map(BigInteger::valueOf))
    val W = mul(lam, derive(c, BigInteger.valueOf(i)))!!
    val e = BigInteger(1, sha(utf8("keykin/ecdh-dleq/1"), unhex(g), unhex(epoch), unhex(state), u32(i), compBytes(W), compBytes(Q), compBytes(Y), compBytes(R1), compBytes(R2))).mod(N)
    mul(zz) == add(R1, mul(e, W)) && mul(zz, Q) == add(R2, mul(e, Y))
} catch (_: Exception) { false }
