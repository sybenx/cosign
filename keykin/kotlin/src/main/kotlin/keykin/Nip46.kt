// NIP-46 at its home (Doors §3.3) for the Kotlin device, ported from the TS reference's device/nip46.ts
// with review 11's fixes: per-site signer keys that never leave the device, bunker:// links bound to the
// first client and dead after 10 minutes, nostrconnect:// codes, the methods and their errors, the
// machinery guard and no decryption of the account's own data (device/doors.ts), requests only within
// 2 minutes and each once, held events kept for the person. Watching (the wake path) follows.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.security.SecureRandom

class Nip46Home(private val d: Device, private val net: RelayNet, private val secp: Secp = Keykin.secp) {
    /** `entry`: the grant store's entry once a client is bound (Doors §1); `offered`: the scopes the link offered. */
    class Grant(val signer: String, val signerSk: ByteArray, var client: String?, val secret: String?, var linkExpires: Long?, val relays: List<String>, var endedAt: Long? = null,
                var entry: String? = null, val offered: List<String> = listOf("sign-in", "post"), val site: String = "")
    class Held(val id: String, val signer: String, val event: Unsigned, val at: Long)
    val grants = LinkedHashMap<String, Grant>()
    val held = LinkedHashMap<String, Held>()
    /** Scopes sites asked for that the person hasn't answered, by signer (Doors §1: asked the first time). */
    val asks = LinkedHashMap<String, MutableSet<String>>()
    @Synchronized fun allowScope(signer: String, scope: String) {
        val g = grants[signer] ?: refuse("unknown_grant"); d.grants.widen(g.entry ?: refuse("unknown_grant"), listOf(scope)); asks[signer]?.remove(scope); d.publishGrantsSoon()
    }
    private fun bind(g: Grant, client: String) {
        g.client = client
        g.entry = d.grants.make(client, g.site, "nip46", client, g.offered, g.relays, g.signer).getString("id")
        d.publishGrantsSoon()
    }
    private fun has(g: Grant, scope: String): Boolean {
        val e = g.entry?.let { d.grants.own[it] }
        // An expired grant grants nothing (review 16 M4).
        if (e != null && scope in d.grants.scopesOf(e) && !Grants.expired(e, net.now, null)) { d.grants.used(e.getString("id")); return true }
        asks.getOrPut(g.signer) { LinkedHashSet() } += scope
        return false
    }
    private fun ask(scope: String) = err("permission: $scope needs your OK on your phone")
    private val seen = LinkedHashMap<String, Long>()
    private var stop: (() -> Unit)? = null
    private val env = Envelope(secp)
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-nip46").also { it.isDaemon = true } }
    private fun rand(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }
    private fun key(): ByteArray = rand(32).also { it[0] = (it[0].toInt() and 0x7f).toByte() }

    init {
        // A wiped or removed device's home goes with it: no grant, held event or signer key stays (review 13 M6).
        d.onGone { sleep(); synchronized(this) { grants.values.forEach { it.signerSk.fill(0) }; grants.clear(); held.clear() } }
        // Sites' requests a watching server kept for this device come here (review 11 M1).
        d.onSiteRequest = { e -> worker.execute { try { handle(e) } catch (_: Exception) {} } }
    }
    fun mintBunker(relays: List<String>, site: String = "", scopes: List<String> = listOf("sign-in", "post")): String {
        val sk = key(); val g = Grant(secp.pub(sk), sk, null, hex(rand(16)), net.now + 600, relays, offered = scopes, site = site)
        grants[g.signer] = g; listen()
        return "bunker://${g.signer}?" + relays.joinToString("&") { "relay=" + java.net.URLEncoder.encode(it, "UTF-8") } + "&secret=${g.secret}"
    }
    fun acceptNostrconnect(uri: String, scopes: List<String> = listOf("sign-in", "post")): Grant {
        val u = URI(uri); if (u.scheme != "nostrconnect") refuse("malformed", "not a nostrconnect code")
        val client = u.host ?: refuse("malformed", "client key")
        if (!Regex("^[0-9a-f]{64}$").matches(client)) refuse("malformed", "client key")
        val q = (u.rawQuery ?: "").split("&").filter { it.contains("=") }.map { it.split("=", limit = 2).let { kv -> kv[0] to URLDecoder.decode(kv[1], "UTF-8") } }
        val relays = q.filter { it.first == "relay" }.map { it.second }.distinct().take(8)
        if (relays.isEmpty() || relays.any { !Regex("^wss?://\\S+$").matches(it) || it.length > 256 }) refuse("malformed", "relays")
        val sk = key(); val g = Grant(secp.pub(sk), sk, null, null, null, relays, offered = scopes, site = q.firstOrNull { it.first == "name" }?.second ?: "")
        bind(g, client); grants[g.signer] = g; listen()
        reply(g, client, JSONObject().put("id", hex(rand(8))).put("result", q.firstOrNull { it.first == "secret" }?.second ?: "ack"), false)
        return g
    }
    fun listen() {
        stop?.invoke()
        val live = grants.values.toList()
        // Off the relay's listener thread: answering signs, and the co-signer's answer arrives on that thread.
        stop = if (live.isEmpty()) null else net.watch(JSONObject().put("kinds", JSONArray(listOf(24133))).put("#p", JSONArray(live.map { it.signer }))) { e -> worker.execute { try { handle(e) } catch (_: Exception) {} } }
    }
    fun sleep() { stop?.invoke(); stop = null }

    /** One request from a site; false when there was nothing to answer. */
    fun handle(e: JSONObject): Boolean {
        if (d.wiped) return false
        val ev = Event.of(Json.obj(e.toString()))
        if (ev.kind != 24133 || seen.containsKey(ev.id) || Math.abs(net.now - ev.createdAt) > 120 || !verifyEvent(ev)) return false
        seen[ev.id] = ev.createdAt; seen.entries.removeIf { net.now - it.value > 120 }
        val g = grants[ev.tag("p")] ?: return false
        var nip04 = false
        val req = try { Json.obj(Nip44.decrypt(ev.content, Nip44.conversationKey(secp, g.signerSk, ev.pubkey))) }
            catch (_: KeykinException) { try { nip04 = true; Json.obj(nip04Decrypt(g.signerSk, ev.pubkey, ev.content)) } catch (_: Exception) { return false } }
        val id = req.opt("id") as? String ?: return false
        val method = req.opt("method") as? String ?: return false
        val params = req.optJSONArray("params")?.let { a -> (0 until a.length()).map { a.get(it).toString() } } ?: emptyList()
        reply(g, ev.pubkey, answer(g, ev.pubkey, method, params).put("id", id), nip04)
        return true
    }

    private fun err(s: String) = JSONObject().put("error", s)
    private fun ok(s: String) = JSONObject().put("result", s)
    internal fun answer(g: Grant, from: String, method: String, params: List<String>): JSONObject {
        if (g.endedAt != null) return err("revoked: this site was disconnected")
        if (method == "connect") {
            if (g.client == null) {
                val exp = g.linkExpires
                if (g.secret == null || params.getOrNull(1) != g.secret || exp == null || net.now > exp) return err("not-connected: this link has expired or is wrong; mint a new one")
                bind(g, from); g.linkExpires = null; return ok("ack")
            }
            return if (from == g.client) ok("ack") else err("not-connected: this link belongs to another client; mint a new one")
        }
        if (from != g.client) return err("not-connected: connect first")
        // Doors §2: never on old news. A home that hasn't caught up within 30 seconds does first.
        if (method != "ping" && net.now - d.lastFetchAt > 30) try { d.fetch() } catch (_: Exception) {}
        // A grant ended on another device (a tombstone, a removal) ends here too.
        if (g.entry != null && d.grants.own[g.entry!!] == null) { end(g); return err("revoked: this site was disconnected") }
        return try {
            when (method) {
                "ping" -> ok("pong")
                "get_public_key" -> if (has(g, "sign-in")) ok(d.g) else ask("sign-in")
                "get_relays" -> ok(JSONObject().also { o -> g.relays.forEach { o.put(it, JSONObject().put("read", true).put("write", true)) } }.toString())
                "switch_relays" -> ok(JSONArray(g.relays).toString())
                "logout" -> { end(g); ok("ack") }
                "sign_event" -> {
                    val x = Json.obj(params.getOrNull(0) ?: refuse("malformed"))
                    // A site's event (§9.5): an empty or absent pubkey is ours; any other is refused.
                    val pk = x.opt("pubkey"); if (pk != null && pk != JSONObject.NULL && pk != "" && pk != d.g) refuse("declined", "the event names another pubkey")
                    val kind = Json.long(x.opt("kind")).toInt()
                    val tags = x.optJSONArray("tags")?.let { t -> (0 until t.length()).map { k -> t.getJSONArray(k).let { a -> (0 until a.length()).map { a.getString(it) } } } } ?: emptyList()
                    siteGuard(kind, tags)
                    val needs = Grants.scopesForEvent(kind, tags, null) ?: return err("declined: a deletion by token, or a token for no host, is never a site's to get signed")
                    for (n in needs) if (!has(g, n)) return ask(n)
                    val content = x.optString("content")
                    val at = if (x.has("created_at")) Json.long(x.get("created_at")) else net.now
                    try { ok(d.sign(kind, content, tags, at).toString()) }
                    catch (e: KeykinException) {
                        if (e.code != "needs_approval") throw e
                        val h = Held(hex(rand(8)), g.signer, Unsigned(d.g, at, kind, tags, content), net.now); held[h.id] = h
                        err("held: approve on your phone")
                    }
                }
                // Encrypting to the account's own key is `post`, to anyone else `dms`; decrypting with others is `dms`,
                // to the account itself released only under the scope its plaintext needs (Doors §1).
                "nip44_encrypt", "nip04_encrypt" -> {
                    val need = if (params[0].lowercase() == d.g) "post" else "dms"; if (!has(g, need)) return ask(need)
                    // An encryption to self is recorded for this grant: evidence for its later decrypts.
                    ok(if (method == "nip44_encrypt") d.nip44(params[0], params[1], true, "${d.pub}:${g.entry}") else d.nip04(params[0], params[1], true))
                }
                "nip44_decrypt", "nip04_decrypt" -> {
                    if (!Regex("^[0-9a-fA-F]{64}$").matches(params[0])) refuse("declined", "a peer key is 32 bytes of hex")
                    val peer = params[0].lowercase()
                    if (peer != d.g) {
                        if (!has(g, "dms")) return ask("dms")
                        return ok(if (method == "nip44_decrypt") d.nip44(peer, params[1], false) else d.nip04(peer, params[1], false))
                    }
                    // To self: a grant with no to-self scope is refused before any round; then the scope the bytes'
                    // evidence and plaintext need, checked whatever it is (review 16 M1, M9), one message for every class.
                    val e = g.entry?.let { d.grants.own[it] }
                    if (e == null || d.grants.scopesOf(e).none { it in setOf("lists", "wallet", "private-data", "dms") }) { has(g, "private-data"); return err("permission: needs your OK on your phone") }
                    val plain = if (method == "nip44_decrypt") d.nip44(peer, params[1], false) else d.nip04(peer, params[1], false)
                    val need = Grants.scopeForDecrypt(d.g, peer, plain, if (method == "nip44_decrypt") params[1] else null, d.evidence, "${d.pub}:${g.entry}")
                    if (need == "malformed") return err("declined: not a canonical payload")
                    if (!has(g, need)) return err("permission: needs your OK on your phone")
                    ok(plain)
                }
                else -> err("unsupported: $method")
            }
        } catch (e: KeykinException) {
            when (e.code) {
                "declined" -> err("declined: " + (e.message ?: "").removePrefix("declined: "))
                "unreachable", "no_server", "no_answer" -> err("try-later: no server answered")
                else -> err("declined: ${e.code}")
            }
        }
    }
    private fun siteGuard(kind: Int, tags: List<List<String>>) = Doors.siteGuard(d, kind, tags)
    /** End a grant here: its key answers `revoked:` from now on, and its entry ends in the grant store. */
    private fun end(g: Grant) { g.endedAt = net.now; g.entry?.let { d.grants.end(d.pub, it); d.publishGrantsSoon() }; asks.remove(g.signer); held.entries.removeIf { it.value.signer == g.signer } }

    private fun reply(g: Grant, to: String, body: JSONObject, nip04: Boolean) {
        val text = body.toString()
        val content = if (nip04) nip04Encrypt(g.signerSk, to, text) else Nip44.encrypt(text, Nip44.conversationKey(secp, g.signerSk, to))
        net.publishEvent(env.sign(g.signerSk, 24133, net.now, listOf(listOf("p", to)), content))
    }
    private fun nip04Key(sk: ByteArray, peer: String) = javax.crypto.spec.SecretKeySpec(secp.ecdhX(sk, peer), "AES")
    private fun nip04Encrypt(sk: ByteArray, peer: String, text: String): String {
        val iv = rand(16); val c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding"); c.init(javax.crypto.Cipher.ENCRYPT_MODE, nip04Key(sk, peer), javax.crypto.spec.IvParameterSpec(iv))
        val b = java.util.Base64.getEncoder(); return b.encodeToString(c.doFinal(utf8(text))) + "?iv=" + b.encodeToString(iv)
    }
    private fun nip04Decrypt(sk: ByteArray, peer: String, text: String): String {
        val p = text.split("?iv="); if (p.size != 2) refuse("malformed")
        val c = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding"); val d64 = java.util.Base64.getDecoder()
        c.init(javax.crypto.Cipher.DECRYPT_MODE, nip04Key(sk, peer), javax.crypto.spec.IvParameterSpec(d64.decode(p[1])))
        return Json.utf8Strict(c.doFinal(d64.decode(p[0])))
    }
}
