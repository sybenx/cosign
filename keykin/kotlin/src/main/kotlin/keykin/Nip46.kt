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

class Nip46Home(private val d: Device, private val net: RelayNet, private val secp: Secp = Secp.Reference) {
    class Grant(val signer: String, val signerSk: ByteArray, var client: String?, val secret: String?, var linkExpires: Long?, val relays: List<String>, var endedAt: Long? = null)
    class Held(val id: String, val signer: String, val event: Unsigned, val at: Long)
    val grants = LinkedHashMap<String, Grant>()
    val held = LinkedHashMap<String, Held>()
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
    fun mintBunker(relays: List<String>): String {
        val sk = key(); val g = Grant(secp.pub(sk), sk, null, hex(rand(16)), net.now + 600, relays)
        grants[g.signer] = g; listen()
        return "bunker://${g.signer}?" + relays.joinToString("&") { "relay=" + java.net.URLEncoder.encode(it, "UTF-8") } + "&secret=${g.secret}"
    }
    fun acceptNostrconnect(uri: String): Grant {
        val u = URI(uri); if (u.scheme != "nostrconnect") refuse("malformed", "not a nostrconnect code")
        val client = u.host ?: refuse("malformed", "client key")
        if (!Regex("^[0-9a-f]{64}$").matches(client)) refuse("malformed", "client key")
        val q = (u.rawQuery ?: "").split("&").filter { it.contains("=") }.map { it.split("=", limit = 2).let { kv -> kv[0] to URLDecoder.decode(kv[1], "UTF-8") } }
        val relays = q.filter { it.first == "relay" }.map { it.second }.distinct().take(8)
        if (relays.isEmpty() || relays.any { !Regex("^wss?://\\S+$").matches(it) || it.length > 256 }) refuse("malformed", "relays")
        val sk = key(); val g = Grant(secp.pub(sk), sk, client, null, null, relays)
        grants[g.signer] = g; listen()
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
    private fun answer(g: Grant, from: String, method: String, params: List<String>): JSONObject {
        if (g.endedAt != null) return err("revoked: this site was disconnected")
        if (method == "connect") {
            if (g.client == null) {
                val exp = g.linkExpires
                if (g.secret == null || params.getOrNull(1) != g.secret || exp == null || net.now > exp) return err("not-connected: this link has expired or is wrong; mint a new one")
                g.client = from; g.linkExpires = null; return ok("ack")
            }
            return if (from == g.client) ok("ack") else err("not-connected: this link belongs to another client; mint a new one")
        }
        if (from != g.client) return err("not-connected: connect first")
        return try {
            when (method) {
                "ping" -> ok("pong")
                "get_public_key" -> ok(d.g)
                "get_relays" -> ok(JSONObject().also { o -> g.relays.forEach { o.put(it, JSONObject().put("read", true).put("write", true)) } }.toString())
                "switch_relays" -> ok(JSONArray(g.relays).toString())
                "logout" -> { g.endedAt = net.now; ok("ack") }
                "sign_event" -> {
                    val x = Json.obj(params.getOrNull(0) ?: refuse("malformed"))
                    // A site's event (§9.5): an empty or absent pubkey is ours; any other is refused.
                    val pk = x.opt("pubkey"); if (pk != null && pk != JSONObject.NULL && pk != "" && pk != d.g) refuse("declined", "the event names another pubkey")
                    val kind = Json.long(x.opt("kind")).toInt()
                    val tags = x.optJSONArray("tags")?.let { t -> (0 until t.length()).map { k -> t.getJSONArray(k).let { a -> (0 until a.length()).map { a.getString(it) } } } } ?: emptyList()
                    siteGuard(kind, tags)
                    val content = x.optString("content")
                    val at = if (x.has("created_at")) Json.long(x.get("created_at")) else net.now
                    try { ok(d.sign(kind, content, tags, at).toString()) }
                    catch (e: KeykinException) {
                        if (e.code != "needs_approval") throw e
                        val h = Held(hex(rand(8)), g.signer, Unsigned(d.g, at, kind, tags, content), net.now); held[h.id] = h
                        err("held: approve on your phone")
                    }
                }
                "nip44_encrypt" -> ok(d.nip44(params[0], params[1], true))
                "nip44_decrypt" -> { mayDecrypt(params[0]); ok(d.nip44(params[0], params[1], false)) }
                "nip04_encrypt" -> ok(d.nip04(params[0], params[1], true))
                "nip04_decrypt" -> { mayDecrypt(params[0]); ok(d.nip04(params[0], params[1], false)) }
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
    /** As device/doors.ts siteGuard: never the account's machinery. */
    private fun siteGuard(kind: Int, tags: List<List<String>>) {
        if (kind == 30242 || kind == 24302) refuse("declined", "account machinery")
        if (kind in 1244..1247) refuse("declined", "a key-family event is the person's own act, never a site's")
        val backups = listOfNotNull(d.view.backup)
        val signposts = backups.map { hex(sha(utf8("keykin-beacon/1"), unhex(it))) }.toSet()
        val dTag = tags.firstOrNull { it.size >= 2 && it[0] == "d" }?.get(1) ?: ""
        if (kind == 30078 && (dTag.lowercase() in signposts || dTag.startsWith("keykin-"))) refuse("declined", "the account's signpost and keykin- data are never a site's to write")
        if (kind == 5) for (t in tags) { val v = (t.getOrNull(1) ?: "").lowercase()
            if (t.getOrNull(0) == "a" && ((signposts.any { v.contains(it) } && v.contains(d.g)) || v.contains(":keykin-"))) refuse("declined", "a deletion of the account's signpost or keykin- data") }
    }
    private fun mayDecrypt(peer: String) { if (peer.lowercase() == d.g) refuse("declined", "the account's own data is not a site's to read") }

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
