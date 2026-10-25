package cc.aaro.cosign.core

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger

/**
 * The signer's half of the group's FROST, matching server/frost.ts exactly.
 * The phone never coordinates, so it only commits, signs its part, and does its
 * part of a threshold ECDH. vectors (src/test/resources/frost.json) pin the two
 * implementations together.
 *
 *   rho_i = int(H_tag("cosign/rho", Y_x || msg || B || be32(i))) mod n
 *   R     = sum_i (D_i + rho_i * E_i)                 negated if R has odd y
 *   c     = int(H_tag("BIP0340/challenge", R_x || Y_x || msg)) mod n
 *   z_i   = s(d_i + rho_i * e_i) + lambda_i * s_i * c         s = -1 if R odd
 */
object Frost {
    val N: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    data class Nonces(val d: BigInteger, val e: BigInteger)
    data class Commit(val idx: Int, val D: String, val E: String) : java.io.Serializable

    fun scalar(b: ByteArray): BigInteger = BigInteger(1, b).mod(N)

    fun bytes32(a: BigInteger): ByteArray {
        val raw = a.mod(N).toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    fun randomScalar(env: Env): BigInteger {
        while (true) {
            val k = BigInteger(1, env.random(32))
            if (k.signum() > 0 && k < N) return k
        }
    }

    private fun mulG(k: BigInteger) = Secp256k1.pubkeyCreate(bytes32(k))
    private fun parse(hex: String) = Secp256k1.pubkeyParse(hex.hexToBytes())
    private fun mul(p: ByteArray, k: BigInteger) = Secp256k1.pubKeyTweakMul(p, bytes32(k))
    private fun add(vararg ps: ByteArray) = if (ps.size == 1) ps[0] else Secp256k1.pubKeyCombine(arrayOf(*ps))
    private fun compress(p: ByteArray) = Secp256k1.pubKeyCompress(p)
    private fun evenY(p: ByteArray) = (p[64].toInt() and 1) == 0
    private fun xOnly(p: ByteArray) = p.copyOfRange(1, 33)
    private fun be32(i: Int) = byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte())

    private fun tagged(tag: String, vararg parts: ByteArray): ByteArray {
        val t = sha256(tag.toByteArray(Charsets.UTF_8))
        return sha256(concat(t, t, *parts))
    }

    fun lagrange(i: Int, participants: List<Int>): BigInteger {
        var num = BigInteger.ONE
        var den = BigInteger.ONE
        for (j in participants) {
            if (j == i) continue
            num = num.multiply(BigInteger.valueOf(j.toLong())).mod(N)
            den = den.multiply(BigInteger.valueOf((j - i).toLong()).mod(N)).mod(N)
        }
        return num.multiply(den.modInverse(N)).mod(N)
    }

    fun commit(idx: Int, env: Env): Pair<Nonces, Commit> {
        val d = randomScalar(env)
        val e = randomScalar(env)
        return Nonces(d, e) to Commit(idx, compress(mulG(d)).toHex(), compress(mulG(e)).toHex())
    }

    /** This signer's share of the signature. The nonces must never be used again. */
    fun partialSign(groupX: String, msg: String, commits: List<Commit>, idx: Int, secret: String, nonces: Nonces): String {
        val y = groupX.hexToBytes()
        val m = msg.hexToBytes()
        require(m.size == 32) { "message must be 32 bytes" }
        val sorted = commits.sortedBy { it.idx }
        require(sorted.map { it.idx }.distinct().size == sorted.size) { "duplicate participant" }
        require(sorted.any { it.idx == idx }) { "signer is not a participant" }
        val list = concat(*sorted.flatMap { listOf(be32(it.idx), it.D.hexToBytes(), it.E.hexToBytes()) }.toTypedArray())

        var myRho = BigInteger.ZERO
        val terms = sorted.map { c ->
            val rho = scalar(tagged("cosign/rho", y, m, list, be32(c.idx)))
            if (c.idx == idx) myRho = rho
            add(parse(c.D), mul(parse(c.E), rho))
        }
        val r = add(*terms.toTypedArray())
        val flip = !evenY(r)
        val ch = scalar(tagged("BIP0340/challenge", xOnly(r), y, m))
        val k = nonces.d.add(myRho.multiply(nonces.e)).mod(N)
        val lam = lagrange(idx, sorted.map { it.idx })
        val s = BigInteger(1, secret.hexToBytes())
        val z = (if (flip) N.subtract(k) else k).add(lam.multiply(s).multiply(ch)).mod(N)
        return bytes32(z).toHex()
    }

    /** lambda_i * s_i * P: this signer's part of the group's shared point with P. */
    fun ecdhPartial(idx: Int, secret: String, participants: List<Int>, peerX: String): String {
        val p = Secp256k1.pubkeyParse(byteArrayOf(2) + peerX.hexToBytes())
        val k = lagrange(idx, participants).multiply(BigInteger(1, secret.hexToBytes())).mod(N)
        return compress(mul(p, k)).toHex()
    }

    /** The share's public point, to check a received share before keeping it. */
    fun sharePub(secret: String): String = compress(mulG(BigInteger(1, secret.hexToBytes()))).toHex()
}
