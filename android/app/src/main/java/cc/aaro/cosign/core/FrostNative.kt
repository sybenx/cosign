package cc.aaro.cosign.core

/**
 * The phone's half of signing, on the Zcash Foundation's FROST (RFC 9591, BIP-340), from
 * ../frost (libcosign_frost.so, built with `cargo ndk`). Strings in, strings out, so it
 * matches the server's WebAssembly build exactly; see frost/src/lib.rs for the shapes.
 * Bad input throws IllegalArgumentException.
 *
 * Frost.kt is the earlier hand-rolled math, kept only for servers not updated yet.
 */
object FrostNative {
    init { System.loadLibrary("cosign_frost") }

    /** `{"nonces": hex, "commit": {"idx", "D", "E"}}`. */
    @JvmStatic external fun commit(group: String, idx: Int, secret: String): String
    @JvmStatic external fun sign(group: String, idx: Int, secret: String, nonces: String, msg: String, commits: String): String
    @JvmStatic external fun verifyPartial(group: String, msg: String, commits: String, idx: Int, z: String): Boolean
    /** `partials`: `[[idx, z], …]`. */
    @JvmStatic external fun aggregate(group: String, msg: String, commits: String, partials: String): String
}
