// App-private data (core 14.25 §4.5): an app's own keys, derived from the account's data key under a domain only that
// app can have. Its identity domain's first segment is exactly `id-` ‖ lowercase hex SHA-256(utf8 identity), granted
// silently and only to the app whose identity it hashes; never by an app list or a hand grant. The identity is worked
// out where the call arrives (the signer process), never taken from the caller:
//   Android  android:<package>:<original signing-certificate SHA-256>   (the first of a v3 lineage; one signer only)
//   Apple    apple:<team id>:<signing identifier>
// Browser extensions derive only under open domains, and Linux and Windows programs have no identity domain.
package keykin

object AppDomains {
    private val ID = Regex("^id-[0-9a-f]{64}$")
    private val LABEL = Regex("^[a-z0-9][a-z0-9.-]*(/[a-z0-9][a-z0-9.-]*)*/(0|[1-9][0-9]*)$")

    /** `id-<hex SHA-256(utf8 identity)>`. */
    fun identityDomain(identity: String): String = "id-" + hex(sha(utf8(identity)))
    fun androidIdentity(pkg: String, originalCertSha256: String): String {
        if (!Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$").matches(pkg)) refuse("bad_caller", "a package name")
        if (!Regex("^[0-9a-f]{64}$").matches(originalCertSha256)) refuse("bad_caller", "a certificate's SHA-256")
        return "android:$pkg:$originalCertSha256"
    }
    /** An identity domain's first segment: `id-` and 64 lowercase hex, exactly; anything else starting `id-` is malformed. */
    fun isIdentity(domain: String): Boolean {
        val first = domain.substringBefore('/')
        if (!first.startsWith("id-")) return false
        if (!ID.matches(first)) refuse("bad_domain", "malformed identity domain")
        return true
    }
    /** The domain for `caller`'s own `label` (lowercase segments ending in a version, like "notes/1"). */
    fun own(identity: String, label: String): String {
        if (!LABEL.matches(label)) refuse("bad_domain", "a label is lowercase segments ending in a version, like marble/devices/1")
        val d = "${identityDomain(identity)}/$label"
        if (d.length > 128) refuse("bad_domain", "a domain is a short string")
        return d
    }
    /** Whether `caller` may derive under `domain`: an identity domain only its own; `ext:` callers open domains only;
     *  `linux:` and `windows:` callers never an identity domain. Refuses otherwise. */
    fun check(caller: String, domain: String) {
        val id = isIdentity(domain)
        when {
            caller.startsWith("ext:") -> if (id) refuse("bad_domain", "extensions derive only under open domains")
            caller.startsWith("linux:") || caller.startsWith("windows:") -> if (id) refuse("bad_domain", "no identity domain on Linux or Windows")
            id && domain.substringBefore('/') != identityDomain(caller) -> refuse("bad_domain", "identity domain of another app")
        }
    }
    /** HKDF-SHA256(empty salt, ikm = dk(S), info = utf8(domain) ‖ 0x00 ‖ bytes), 32 bytes. */
    fun derive(dk: ByteArray, domain: String, bytes: ByteArray): ByteArray = hkdf32(dk, utf8(domain) + byteArrayOf(0) + bytes)
}
