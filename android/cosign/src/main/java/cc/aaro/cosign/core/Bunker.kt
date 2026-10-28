package cc.aaro.cosign.core

import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * This device's own NIP-46 front: each site gets a signer key of its own, and only your
 * devices hold it (COSIGN.md §6.1). A site encrypts its requests to that key, so whoever
 * holds it reads them — DM text included. Servers run by anyone else never get it: they see
 * only that something was sent to it (the event's `p` tag), which is enough to wake this
 * phone by push and nothing more.
 *
 * Follows server/core/bunker.ts, the reference, line for line where it can. No I/O of its
 * own: the [Deps] are this device's rounds with a server (as for an app on the phone,
 * NIP-55), its relays, and its storage.
 */
class Bunker(keys: List<SiteKey>, private val d: Deps) {

    /** One site's mailbox. See bunker.ts `SiteKey`. */
    data class SiteKey(
        val sk: String, val pk: String, val origin: String, val relays: List<String>,
        val client: String? = null, val t: String? = null, val expires: Long? = null,
        val dm: Boolean? = null, val added: Long, val by: String, val revoked: Long? = null,
    ) {
        fun toMap(): Map<String, Any?> = mapOf("sk" to sk, "pk" to pk, "origin" to origin, "relays" to relays, "client" to client,
            "t" to t, "expires" to expires, "dm" to dm, "added" to added, "by" to by, "revoked" to revoked).filterValues { it != null }

        companion object {
            fun fromMap(x: Any?): SiteKey? {
                val m = x as? Map<*, *> ?: return null
                val sk = m["sk"] as? String ?: return null
                val pk = m["pk"] as? String ?: return null
                if (!isHex32(sk) || !isHex32(pk) || publicKeyHex(sk.hexToBytes()) != pk) return null
                return SiteKey(sk, pk, (m["origin"] as? String ?: "a site").take(200),
                    (m["relays"] as? List<*>)?.filterIsInstance<String>()?.filter { relayOk(it) }?.map { normRelay(it) }?.take(8) ?: emptyList(),
                    (m["client"] as? String)?.takeIf { isHex32(it) }, m["t"] as? String, m["expires"] as? Long, m["dm"] as? Boolean,
                    m["added"] as? Long ?: 0, m["by"] as? String ?: "", m["revoked"] as? Long)
            }
        }
    }

    interface Deps {
        fun groupX(): String
        fun relays(): List<String>
        /** This device's member key, as [SiteKey.by]. */
        val me: String
        /** Sign for this grant: the device's round with a server. Blocks; throws with a reason. */
        fun sign(grant: String, origin: String, dm: Boolean, ev: Event): Event
        /** The shared x with a peer, from this device's shares and a server's. Blocks. */
        fun ecdh(grant: String, origin: String, peerX: String): ByteArray
        /** Ask the person once: may this site read and send messages? Blocks for the answer. */
        fun askDms(origin: String): Boolean
        /** A site connected: tell the servers (app_grant with the mailbox's public key). */
        fun granted(k: SiteKey)
        /** A site signed out: the grant goes everywhere. */
        fun revoked(k: SiteKey)
        /** The mailboxes changed: save them, subscribe again, hand copies to other devices. */
        fun changed(keys: List<SiteKey>)
        fun publish(e: Event)
        val env: Env
    }

    @Volatile var keys: List<SiteKey> = keys
        private set
    private val answers = ConcurrentHashMap<String, Triple<Long, String, Boolean>>() // body, nip44?
    private val working = ConcurrentHashMap.newKeySet<String>()
    private val answeredElsewhere = ConcurrentHashMap.newKeySet<String>()
    private val worker = Executors.newSingleThreadScheduledExecutor()
    private fun now() = d.env.now()

    // --- Opening a mailbox -----------------------------------------------------------------

    /** A sign-in code (QRST `signer-ticket`): a new mailbox, and the ticket that opens it once. */
    fun ticket(origin: String, ttl: Long = 900): SiteKey {
        val sk = generateSecretKey(d.env)
        val k = SiteKey(sk.toHex(), publicKeyHex(sk), origin.take(200), d.relays().map { normRelay(it) },
            t = d.env.random(16).toHex(), expires = now() + ttl, added = now(), by = d.me)
        update { tidy(it + k) }
        return k
    }

    /** A nostrconnect:// code this phone scanned: answer it from a new mailbox of the site's own. */
    fun nostrconnect(client: String, relays: List<String>, secret: String, origin: String): SiteKey? {
        if (!isHex32(client) || secret.isBlank()) return null
        val siteRelays = relays.filter { relayOk(it) }.map { normRelay(it) }.distinct().take(4)
        if (siteRelays.isEmpty()) return null
        keys.firstOrNull { it.client == client }?.let { had ->
            // Scanned again: that's you letting it back in.
            val back = if (had.revoked != null) had.copy(revoked = null).also { b -> update { ks -> ks.map { if (it.pk == b.pk) b else it } }; d.granted(b) } else had
            connectReply(back, secret)
            return back
        }
        val sk = generateSecretKey(d.env)
        val k = SiteKey(sk.toHex(), publicKeyHex(sk), origin.take(200), (siteRelays + d.relays().map { normRelay(it) }).distinct(),
            client = client, added = now(), by = d.me)
        update { it + k }
        d.granted(k)
        connectReply(k, secret)
        return k
    }

    private fun connectReply(k: SiteKey, secret: String) {
        val client = k.client ?: return
        val body = Json.stringify(mapOf("id" to d.env.random(8).toHex(), "result" to secret))
        reply(k, client, true, body)
        worker.schedule({ reply(k, client, true, body) }, 3, TimeUnit.SECONDS)
    }

    /** A copy from another of your devices, sealed to this one. */
    fun adopt(x: Any?): Boolean {
        val k = SiteKey.fromMap(x) ?: return false
        if (keys.any { it.pk == k.pk }) return false
        update { it + k }
        return true
    }

    /** You removed a site (anywhere): its mailbox answers "revoked" for a day, then goes. */
    fun forget(client: String) {
        if (keys.none { it.client == client && it.revoked == null }) return
        update { ks -> tidy(ks.map { if (it.client == client && it.revoked == null) it.copy(revoked = now(), dm = null) else it }) }
    }

    private fun tidy(ks: List<SiteKey>): List<SiteKey> {
        val t = now()
        return ks.filter { k -> if (k.revoked != null) k.revoked > t - 86_400 else k.client != null || (k.expires ?: 0) > t - 3600 }
    }

    @Synchronized private fun update(f: (List<SiteKey>) -> List<SiteKey>) { keys = f(keys); d.changed(keys) }

    /** What to read: requests to the mailboxes, and their answers, to tell another device answered. */
    fun filters(): List<Map<String, Any>> {
        val pks = keys.map { it.pk }
        return if (pks.isEmpty()) emptyList() else listOf(mapOf("kinds" to listOf(KIND_NIP46), "#p" to pks), mapOf("kinds" to listOf(KIND_NIP46), "authors" to pks))
    }

    fun relays(): List<String> = keys.flatMap { it.relays }.distinct()

    // --- Answering -------------------------------------------------------------------------

    fun onEvent(e: Event) {
        if (e.kind != KIND_NIP46 || now() - e.createdAt > 30) return
        val from = keys.firstOrNull { it.pk == e.pubkey }
        if (from != null) {
            val to = e.firstTag("p") ?: return
            open(from, to, e.content)?.first?.get("id")?.let { answeredElsewhere.add("$to:$it") }
            return
        }
        val to = e.tags.filter { it.firstOrNull() == "p" }.mapNotNull { it.getOrNull(1) }
        val k = keys.firstOrNull { it.pk in to } ?: return
        val (req, nip44) = open(k, e.pubkey, e.content) ?: return
        val id = req["id"] as? String ?: return
        val method = req["method"] as? String ?: return
        val key = "${e.pubkey}:$id"
        answers[key]?.let { return reply(k, e.pubkey, it.third, it.second) }
        if (!working.add(key)) return
        // A copy of another device's mailbox waits a moment for that device, which normally answers.
        val delay = if (k.by != d.me) 2500L else 0L
        worker.schedule({
            if (delay > 0 && (answeredElsewhere.contains(key) || answers.containsKey(key))) { working.remove(key); return@schedule }
            val body = try { handle(k.pk, e.pubkey, method, (req["params"] as? List<*>)?.map { it?.toString() ?: "" } ?: emptyList()) }
                       catch (x: Exception) { mapOf("error" to (x.message ?: x.toString())) }
            val text = Json.stringify(mapOf("id" to id) + body)
            answers[key] = Triple(System.currentTimeMillis(), text, nip44)
            working.remove(key)
            val current = keys.firstOrNull { it.pk == k.pk } ?: k
            reply(current, e.pubkey, nip44, text)
            worker.schedule({ reply(current, e.pubkey, nip44, text) }, 3, TimeUnit.SECONDS)
            answers.entries.removeIf { System.currentTimeMillis() - it.value.first > 120_000 }
            if (answeredElsewhere.size > 2000) answeredElsewhere.clear()
        }, delay, TimeUnit.MILLISECONDS)
    }

    private fun handle(mailbox: String, client: String, method: String, p: List<String>): Map<String, Any?> {
        val k = keys.firstOrNull { it.pk == mailbox } ?: return mapOf("error" to "revoked: Access for this site was removed.")
        if (k.revoked != null) return mapOf("error" to "revoked: Access for this site was removed. Connect it again from your phone.")
        if (method == "connect") {
            if (k.client != null) return if (k.client == client) mapOf("result" to "ack") else mapOf("error" to "bad-ticket: This code was already used by another site. Scan a new one.")
            if (k.t == null || p.getOrNull(1) != k.t || (k.expires ?: 0) < now()) return mapOf("error" to "bad-ticket: This ticket is not valid. Scan the code again with your phone.")
            val c = k.copy(client = client, t = null, expires = null)
            update { ks -> ks.map { if (it.pk == c.pk) c else it } }
            d.granted(c)
            return mapOf("result" to "ack")
        }
        if (method == "ping") return mapOf("result" to "pong")
        if (k.client != client) return mapOf("error" to "not-connected: Not connected. Scan this site’s code with your phone.")
        return when (method) {
            "logout" -> {
                update { ks -> ks.map { if (it.pk == k.pk) it.copy(revoked = now(), dm = null) else it } }
                d.revoked(k)
                mapOf("result" to "ack")
            }
            "get_public_key" -> mapOf("result" to d.groupX())
            "switch_relays" -> mapOf("result" to Json.stringify(k.relays))
            "get_relays" -> mapOf("result" to Json.stringify(k.relays.associateWith { mapOf("read" to true, "write" to true) }))
            "sign_event" -> {
                val t = Json.parse(p.getOrNull(0) ?: "{}") as? Map<*, *> ?: return mapOf("error" to "bad event")
                val kind = (t["kind"] as? Long)?.toInt() ?: return mapOf("error" to "bad event")
                val content = t["content"] as? String ?: return mapOf("error" to "bad event")
                val tags = (t["tags"] as? List<*>)?.map { tag -> (tag as? List<*>)?.map { it.toString() } ?: return mapOf("error" to "bad event") } ?: return mapOf("error" to "bad event")
                val ev = Event(d.groupX(), t["created_at"] as? Long ?: now(), kind, tags, content).withId()
                mapOf("result" to d.sign(client, k.origin, k.dm == true, ev).toJson())
            }
            "nip44_encrypt", "nip44_decrypt", "nip04_encrypt", "nip04_decrypt" -> {
                val peer = p.getOrNull(0)
                if (!isHex32(peer)) return mapOf("error" to "bad peer")
                var dm = k.dm
                if (dm == null) {
                    dm = d.askDms(k.origin)
                    update { ks -> ks.map { if (it.pk == k.pk) it.copy(dm = dm) else it } }
                }
                if (!dm) return mapOf("error" to "not-allowed: You didn’t let this site read or send your messages.")
                val x = d.ecdh(client, k.origin, peer!!)
                val text = p.getOrNull(1) ?: ""
                val result = when (method) {
                    "nip44_encrypt" -> Nip44.encrypt(text, Nip44.conversationKeyFromShared(x), d.env.random(32))
                    "nip44_decrypt" -> Nip44.decrypt(text, Nip44.conversationKeyFromShared(x))
                    else -> aes(x, text, method == "nip04_decrypt")
                }
                mapOf("result" to result)
            }
            else -> mapOf("error" to "unsupported method $method")
        }
    }

    // --- The wire --------------------------------------------------------------------------

    /** A request (or another device's answer) in either encryption a NIP-46 client may use; true for nip44. */
    private fun open(k: SiteKey, other: String, content: String): Pair<Map<*, *>, Boolean>? {
        val sk = k.sk.hexToBytes()
        try { return (Json.parse(Nip44.decrypt(content, Nip44.conversationKey(sk, other))) as? Map<*, *> ?: return null) to true } catch (_: Exception) {}
        try { return (Json.parse(aes(Secp.sharedX(sk, other.hexToBytes()), content, true)) as? Map<*, *> ?: return null) to false } catch (_: Exception) {}
        return null
    }

    private fun reply(k: SiteKey, client: String, nip44: Boolean, body: String) {
        val sk = k.sk.hexToBytes()
        val content = if (nip44) Nip44.encrypt(body, Nip44.conversationKey(sk, client), d.env.random(32)) else aes(Secp.sharedX(sk, client.hexToBytes()), body, false)
        d.publish(Event.sign(k.pk, now(), KIND_NIP46, listOf(listOf("p", client)), content, sk, d.env))
    }

    private fun aes(key: ByteArray, text: String, decrypt: Boolean): String {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val spec = SecretKeySpec(key, "AES")
        if (!decrypt) {
            val iv = d.env.random(16)
            c.init(Cipher.ENCRYPT_MODE, spec, IvParameterSpec(iv))
            return Base64.getEncoder().encodeToString(c.doFinal(text.toByteArray())) + "?iv=" + Base64.getEncoder().encodeToString(iv)
        }
        val (ct, iv) = text.split("?iv=").let { it[0] to it.getOrElse(1) { "" } }
        c.init(Cipher.DECRYPT_MODE, spec, IvParameterSpec(Base64.getDecoder().decode(iv)))
        return String(c.doFinal(Base64.getDecoder().decode(ct)))
    }

    companion object {
        const val KIND_NIP46 = 24133
        fun relayOk(r: String) = Regex("^wss?://\\S+$").matches(r) && r.length < 200
        fun normRelay(u: String) = u.trim().trimEnd('/').lowercase()
    }
}
