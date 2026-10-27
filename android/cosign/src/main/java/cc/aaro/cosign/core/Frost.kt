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

    // --- The proof that a partial is the share's (server/frost.ts ecdhProve/ecdhVerify) -------
    //
    // A partial on its own is unverifiable, so one wrong contribution — a stale share, a
    // corrupted copy at rest, a dishonest partner — makes this phone derive a value nobody else
    // has, and the only symptom is a NIP-44 MAC failure wherever the plaintext was wanted.
    // Chaum-Pedersen, over the share point everyone can see:
    //
    //   v random;  R1 = v*G;  R2 = v*Q
    //   c = int(H_tag("cosign/ecdh-dleq", be32(i) || be32(participants…) || Q_x || L || A || R1 || R2)) mod n
    //   z = v + c * lambda_i * s_i             L = lambda_i * sharePub_i,  A = the partial
    //   check  z*G == R1 + c*L   and   z*Q == R2 + c*A

    data class EcdhPart(val idx: Int, val point: String, val proof: String)

    private fun dleqChallenge(idx: Int, participants: List<Int>, peerX: String, L: ByteArray, A: ByteArray, R1: ByteArray, R2: ByteArray): BigInteger =
        scalar(tagged("cosign/ecdh-dleq",
            be32(idx),
            concat(*participants.sorted().map { be32(it) }.toTypedArray()),
            peerX.hexToBytes(),
            compress(L), compress(A), compress(R1), compress(R2)))

    /** The challenge over hex points, so a vector can pin the bytes without a random nonce. */
    fun dleqChallengeForTest(idx: Int, participants: List<Int>, peerX: String, l: String, a: String, r1: String, r2: String): BigInteger =
        dleqChallenge(idx, participants, peerX, parse(l), parse(a), parse(r1), parse(r2))

    /** This share's partial, with the proof that it is this share's. */
    fun ecdhProve(idx: Int, secret: String, participants: List<Int>, peerX: String, env: Env): EcdhPart {
        val q = Secp256k1.pubkeyParse(byteArrayOf(2) + peerX.hexToBytes())
        val k = lagrange(idx, participants).multiply(BigInteger(1, secret.hexToBytes())).mod(N)
        require(k.signum() != 0) { "degenerate share" }
        val a = mul(q, k)
        val l = mulG(k)
        while (true) {
            val v = randomScalar(env)
            val r1 = mulG(v)
            val r2 = mul(q, v)
            val c = dleqChallenge(idx, participants, peerX, l, a, r1, r2)
            if (c.signum() == 0) continue // a challenge of zero proves nothing
            val z = v.add(c.multiply(k)).mod(N)
            return EcdhPart(idx, compress(a).toHex(), compress(r1).toHex() + compress(r2).toHex() + bytes32(z).toHex())
        }
    }

    /** Check a partial against the share point in the member list. False for anything malformed. */
    fun ecdhVerify(idx: Int, participants: List<Int>, peerX: String, sharePub: String, point: String, proof: String): Boolean = try {
        if (proof.length != 66 + 66 + 64) false else {
            val r1 = parse(proof.substring(0, 66))
            val r2 = parse(proof.substring(66, 132))
            val z = BigInteger(1, proof.substring(132).hexToBytes())
            if (z.signum() <= 0 || z >= N) false else {
                val q = Secp256k1.pubkeyParse(byteArrayOf(2) + peerX.hexToBytes())
                val a = parse(point)
                val lam = lagrange(idx, participants)
                if (lam.signum() == 0) false else {
                    val l = mul(parse(sharePub), lam)
                    val c = dleqChallenge(idx, participants, peerX, l, a, r1, r2)
                    if (c.signum() == 0) false
                    else compress(mulG(z)).contentEquals(compress(add(r1, mul(l, c)))) &&
                        compress(mul(q, z)).contentEquals(compress(add(r2, mul(a, c))))
                }
            }
        }
    } catch (_: Exception) { false }
}
