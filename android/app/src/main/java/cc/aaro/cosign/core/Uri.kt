package cc.aaro.cosign.core

import java.net.IDN
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder

// The pairing address of spec §11.2: one https link whose every parameter lives in
// the fragment, so that neither the burner key nor the relay list reaches the host.
//
//   https://<host>/<path>#v=1&mode=<offer|request>&p=<profile-id>&npub=<npub>
//                         &check=<none|compare|type>&token=<32 hex>
//                         [&relay=<wss url>]*[&origin=<claimed-origin>]

enum class Mode(val wire: String) { OFFER("offer"), REQUEST("request") }
enum class Role { SENDER, RECEIVER }

/** The role a device takes when it scans a code of this mode. */
fun scannerRole(mode: Mode): Role = if (mode == Mode.OFFER) Role.SENDER else Role.RECEIVER

/** The mode of the code a device shows when it has this role. */
fun showingMode(role: Role): Mode = if (role == Role.RECEIVER) Mode.OFFER else Mode.REQUEST

data class PairingParams(
    val mode: Mode,
    val profile: String,
    /** Burner public key of the device showing the code, 32 bytes of hex. */
    val pub: String,
    val check: CodeCheck,
    val token: String,
    val relays: List<String>,
    /** Present if and only if the showing device is a web client. An unverified claim. */
    val origin: String? = null,
)

class UriException(val code: String) : Exception("pairing link: $code")

object PairingUri {
    private val TOKEN = Regex("^[0-9a-f]{${TOKEN_BYTES * 2}}$")
    private val LOOPBACK = setOf("localhost", "127.0.0.1", "[::1]", "::1")

    fun isToken(value: String?): Boolean = value != null && TOKEN.matches(value)

    /** Whether a relay on this machine may be used at all. Only tests turn it on. */
    @Volatile var allowLoopback = false

    /** §11.3a's private-network address, plus Tailscale's names, which resolve only on a tailnet. */
    fun isPrivateHost(hostname: String): Boolean {
        val h = hostname.lowercase().trimEnd('.')
        if (h in LOOPBACK || Regex("\\.(localhost|local|internal|home\\.arpa|ts\\.net)$").containsMatchIn(h)) return true
        val bare = h.removePrefix("[").removeSuffix("]")
        if (bare.contains(':')) {
            Regex("^::ffff:([0-9a-f]{1,4}):[0-9a-f]{1,4}$").find(bare)?.let {
                val high = it.groupValues[1].toInt(16)
                return privateIpv4(high shr 8, high and 0xff)
            }
            Regex("^::ffff:(\\d+)\\.(\\d+)\\.\\d+\\.\\d+$").find(bare)?.let {
                return privateIpv4(it.groupValues[1].toInt(), it.groupValues[2].toInt())
            }
            return bare == "::1" || Regex("^(f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)").containsMatchIn(bare)
        }
        val m = Regex("^(\\d+)\\.(\\d+)\\.\\d+\\.\\d+$").find(h) ?: return false
        return privateIpv4(m.groupValues[1].toInt(), m.groupValues[2].toInt())
    }

    private fun privateIpv4(a: Int, b: Int): Boolean =
        a == 10 || a == 127 || a == 0 || (a == 172 && b in 16..31) || (a == 192 && b == 168) ||
            (a == 169 && b == 254) || (a == 100 && b in 64..127)

    /** Canonical form of a relay URL, or null if it is not one this client will use. */
    fun normalizeRelayUrl(input: String): String? {
        val u = try { URI(input.trim()) } catch (_: Exception) { return null }
        val scheme = u.scheme?.lowercase() ?: return null
        val host = u.host?.lowercase() ?: return null
        val local = host in LOOPBACK
        if (local && !allowLoopback) return null
        if (scheme != "wss" && !(scheme == "ws" && local)) return null
        if (u.rawUserInfo != null) return null
        val port = if (u.port == -1 || (scheme == "wss" && u.port == 443) || (scheme == "ws" && u.port == 80)) "" else ":${u.port}"
        val path = if (u.rawPath.isNullOrEmpty() || u.rawPath == "/") "" else u.rawPath
        val query = if (u.rawQuery != null) "?${u.rawQuery}" else ""
        val hostOut = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        return "$scheme://$hostOut$port$path$query"
    }

    /** Canonical origin, ASCII (a non-ASCII host is shown as punycode per §9.1), or null. */
    fun normalizeOrigin(input: String): String? {
        val u = try { URI(input.trim()) } catch (_: Exception) { return null }
        val scheme = u.scheme?.lowercase() ?: return null
        if (scheme != "https" && scheme != "http") return null
        val host = try { IDN.toASCII(u.host ?: return null).lowercase() } catch (_: Exception) { return null }
        if (host.length > 253 || host.split('.').any { it.length > 63 }) return null
        val port = if (u.port == -1 || (scheme == "https" && u.port == 443) || (scheme == "http" && u.port == 80)) "" else ":${u.port}"
        return "$scheme://$host$port"
    }

    private fun enc(value: String): String =
        URLEncoder.encode(value, "UTF-8").replace("+", "%20").replace("%3A", ":").replace("%2F", "/")

    fun build(base: String, p: PairingParams): String {
        require(PROFILE_ID.matches(p.profile)) { "pairing link: bad profile identifier" }
        require(p.relays.size in 1..MAX_RELAYS) { "pairing link: needs 1 to 4 relays" }
        require(isToken(p.token)) { "pairing link: bad token" }
        val parts = mutableListOf("v=$VERSION", "mode=${p.mode.wire}", "p=${p.profile}", "npub=${Nip19.npub(p.pub)}", "check=${p.check.wire}", "token=${p.token}")
        for (relay in p.relays) parts += "relay=" + enc(normalizeRelayUrl(relay) ?: throw IllegalArgumentException("pairing link: bad relay"))
        p.origin?.let { parts += "origin=" + enc(normalizeOrigin(it) ?: throw IllegalArgumentException("pairing link: bad origin")) }
        return base.substringBefore('#') + "#" + parts.joinToString("&")
    }

    /** The scheme every implementation registers, by which a bounce page hands a code to an installed app (§11.2c). */
    const val HANDOFF_SCHEME = "qrst"

    /** `<scheme>://<npub>?<parameters>`: the form of §11.2c and §12.3. */
    private val SCHEME_FORM = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*)://(npub1[02-9ac-hj-np-zA-Z]+)/?\\?([^#]*)$")

    /** True for a pairing URI in the `qrst:` handoff form (§11.2c). */
    fun isHandoff(text: String): Boolean =
        SCHEME_FORM.find(text.trim())?.groupValues?.get(1)?.lowercase() == HANDOFF_SCHEME

    /** The parameters, from the https fragment (§11.2) or the `qrst:` form. No profile scheme is registered here (§12.3). */
    private fun parameters(text: String): String? {
        SCHEME_FORM.find(text)?.let { m ->
            return if (m.groupValues[1].lowercase() == HANDOFF_SCHEME) "npub=${m.groupValues[2].lowercase()}&${m.groupValues[3]}" else null
        }
        return if ('#' in text) text.substringAfter('#') else text
    }

    fun looksLikePairing(text: String): Boolean {
        val fragment = parameters(text.trim()) ?: return false
        return Regex("(^|&)npub=npub1").containsMatchIn(fragment) && Regex("(^|&)v=").containsMatchIn(fragment)
    }

    /** URLSearchParams semantics: split on &, then =, `+` is a space, percent-decoding. */
    private fun query(fragment: String): List<Pair<String, String>> =
        fragment.split('&').filter { it.isNotEmpty() }.map {
            val k = it.substringBefore('=')
            val v = if ('=' in it) it.substringAfter('=') else ""
            dec(k) to dec(v)
        }

    private fun dec(s: String): String = try { URLDecoder.decode(s, "UTF-8") } catch (_: Exception) { s }

    /**
     * Parses a pairing link, its `qrst:` handoff form, a bare fragment, or the parameters alone. Rejects an
     * unknown `v`, a missing `mode`, `p` or token, and a bad key checksum (§11.2, §12.1).
     * A missing or unknown `check` reads as `type`.
     */
    fun parse(input: String): PairingParams {
        val text = input.trim()
        if (!looksLikePairing(text)) throw UriException("not-a-pairing-link")
        val q = query(parameters(text)!!)
        fun get(name: String) = q.firstOrNull { it.first == name }?.second

        if (get("v") != VERSION.toString()) throw UriException("unknown-version")
        val mode = Mode.entries.firstOrNull { it.wire == get("mode") } ?: throw UriException("missing-mode")
        val profile = get("p")
        if (profile == null || !PROFILE_ID.matches(profile)) throw UriException("missing-profile")
        val pub = try { Nip19.npubDecode(get("npub") ?: "") } catch (_: Exception) { throw UriException("bad-key") }
        val token = get("token")
        if (!isToken(token)) throw UriException("bad-token")
        val check = CodeCheck.parseOrType(get("check"))

        val relays = mutableListOf<String>()
        for ((k, v) in q) {
            if (k != "relay") continue
            val relay = normalizeRelayUrl(v) ?: throw UriException("bad-relay")
            if (relay !in relays) relays += relay
        }
        if (relays.isEmpty()) throw UriException("no-relays")
        val origin = get("origin")?.let { normalizeOrigin(it) ?: throw UriException("bad-origin") }
        return PairingParams(mode, profile, pub, check, token!!, relays.take(MAX_RELAYS), origin)
    }
}
