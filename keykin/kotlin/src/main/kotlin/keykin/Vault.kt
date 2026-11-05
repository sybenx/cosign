// The device calls for vault apps on the same machine (Doors 20 §3.7; vaults.md draft 7.13 §4.5, §12.2–12.3), as
// device/vaultcalls.ts: once the person grants an app all three open domains together (one question for the set),
// it gets `ksig`, `derive` under the owner and keyring domains, account signatures for kinds 4810, 4811 and 30811
// (each a normal co-signed round; a kind 5 only of those, by the account, through Device policy), an invitation
// call that seals and wraps a kind-4812 rumor itself, a NIP-59 unwrap answered only for a 4812 whose seal signer is
// its pubkey, and a NIP-44 decrypt answered only for a vault payload. Never a general encrypt, never a rumor through
// `decrypt`, nothing else of the account's. The grant is this device's only, kept in its snapshot, gone with a wipe.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

class VaultCalls(private val d: Device) {
    companion object {
        const val KSIG = "nostr-vault/ksig/1"
        val DERIVE_DOMAINS = setOf("nostr-vault/owner/1", "nostr-vault/keyring/1")
        /** NIP-59: a seal's and a wrap's created_at is up to two days in the past. */
        private const val TWO_DAYS = 2 * 24 * 3600L
        private val HEX64 = Regex("^[0-9a-f]{64}$")
        private fun no(why: String): Nothing = refuse("declined", why)
    }
    private val apps = LinkedHashSet<String>()
    private val rnd = SecureRandom()

    init {
        d.carriedPart("vaultApps")?.optJSONArray("apps")?.let { a -> for (k in 0 until a.length()) (a.opt(k) as? String)?.let { apps += it } }
        if (apps.isNotEmpty()) DERIVE_DOMAINS.forEach { MemberSig.register(it) }
        d.snapshotParts["vaultApps"] = { synchronized(this) { JSONObject().put("apps", JSONArray(apps.toList())) } }
        d.onGone { synchronized(this) { apps.clear() } }
    }

    /** The person said yes to the one question for the set. */
    fun allow(app: String) {
        if (app.isEmpty() || app.length > 256) refuse("malformed", "an app id")
        if (d.wiped) refuse("wiped")
        DERIVE_DOMAINS.forEach { MemberSig.register(it) }
        synchronized(this) { apps += app }; d.saveNow()
    }
    fun revoke(app: String) { if (synchronized(this) { apps.remove(app) }) d.saveNow() }
    fun allowed(): List<String> = synchronized(this) { apps.sorted() }
    private fun need(app: String) {
        if (d.wiped) refuse("wiped")
        if (synchronized(this) { app !in apps }) no("this app hasn't been granted your vaults on this device")
    }

    /** The member key's signature of a vault root: `mk` and `ksig` for its device cert. */
    fun ksig(app: String, root: ByteArray): Pair<String, String> {
        need(app)
        if (root.size != 32) refuse("malformed", "a vault root is 32 bytes")
        val (sig, key) = d.signAsMember(KSIG, root)
        return key to sig
    }
    fun derive(app: String, ids: List<String>, domain: String, bytes: ByteArray): ByteArray {
        need(app)
        if (domain !in DERIVE_DOMAINS) no("a vault app derives only under nostr-vault/owner/1 and nostr-vault/keyring/1")
        return d.derive(ids, domain, bytes)
    }
    fun current(app: String): Pair<List<String>, String> { need(app); return d.currentState() }
    fun states(app: String): List<Pair<List<String>, String>> { need(app); return d.dataStates() }

    /** Kinds 4810, 4811 and 30811 as a normal co-signed round; a kind 5 of only those, through Device policy. A Held
     *  deletion waits for the person and is `try-later` here. */
    fun sign(app: String, kind: Int, content: String, tags: List<List<String>>, createdAt: Long = d.now): JSONObject {
        need(app)
        val owner = "vault:$app"
        if (kind in Doors.VAULT_KINDS) return d.sign(kind, content, tags, createdAt, owner)
        if (kind != 5) no("a vault app gets signatures for kinds 4810, 4811 and 30811 only")
        vaultTargets(tags)
        val e = Unsigned(d.g, createdAt, 5, tags, content)
        val (gate, signed) = d.guard.serve(e, owner, listOf("sign-in", "post")) { d.sign(5, content, tags, createdAt, owner) }
        if (signed != null) return signed
        gate.error?.let { err -> val code = err.substringBefore(": "); refuse(if (code == "try-later") "try-later" else "declined", err.substringAfter(": ")) }
        refuse("try-later", "held for you on your phone")
    }
    private fun vaultTargets(tags: List<List<String>>) {
        val es = ArrayList<String>(); var n = 0
        for (t in tags) {
            if (t.size < 2) continue
            if (t[0] == "k" && t[1].toIntOrNull() !in Doors.VAULT_KINDS) no("a deletion of something other than vault machinery")
            if (t[0] == "a") {
                val p = t[1].split(':')
                if (p[0].toIntOrNull() !in Doors.VAULT_KINDS || p.getOrNull(1)?.lowercase() != d.g) no("a deletion of something other than the account's vault machinery")
                n++
            }
            if (t[0] == "e") { es += t[1].lowercase(); n++ }
        }
        if (n == 0) no("a deletion with no target")
        val unknown = es.filter { d.history.get(it) == null }
        val found = (if (unknown.isEmpty()) emptyList() else d.lookupEvents(unknown, emptyList())).associateBy { it.id }
        for (id in es) {
            val x = d.history.get(id) ?: found[id] ?: refuse("try-later", "this device can't see one of the events to delete")
            if (x.pubkey != d.g || x.kind !in Doors.VAULT_KINDS) no("a deletion of something other than the account's vault machinery")
        }
    }

    private fun past() = d.now - Math.floorMod(rnd.nextLong(), TWO_DAYS)
    /** NIP-59 by the account: `rumor` (kind 4812, pubkey the account, unsigned) encrypted to `recipient` in a kind-13
     *  seal the account signs, wrapped in a kind 1059 from a one-time key. The wrap, for the app to publish. */
    fun invite(app: String, rumor: JSONObject, recipient: String): JSONObject {
        need(app)
        if (!HEX64.matches(recipient)) refuse("malformed", "recipient")
        if ((rumor.opt("kind") as? Number)?.toLong() != Doors.KIND_VAULT_INVITE.toLong()) no("an invitation is a kind-4812 rumor")
        if (rumor.opt("pubkey") != d.g) no("an invitation is by this account")
        if (rumor.has("sig")) no("a rumor is unsigned")
        val given = rumor.opt("id") as? String
        val r = JSONObject(rumor.toString()).put("id", "0".repeat(64))
        val shaped = Event.shape(r, "rumor")
        val id = eventId(shaped)
        if (given != null && given != id) refuse("malformed", "the rumor id differs from its fields")
        val content = d.nip44(recipient, Jcs.of(r.put("id", id)), true, "vault:$app")
        val seal = d.sign(13, content, emptyList(), past(), "vault:$app")
        val eph = ByteArray(32).also { rnd.nextBytes(it) }
        return Envelope(Keykin.secp).sign(eph, 1059, past(), listOf(listOf("p", recipient)), Nip44.encrypt(Jcs.of(seal), Nip44.conversationKey(Keykin.secp, eph, recipient)))
    }

    /** A gift wrap to the account, answered only for a kind-4812 rumor whose seal is signed by its pubkey: the rumor and
     *  the seal's pubkey. Anything else is refused without saying what it held. */
    fun unwrap(app: String, wrap: JSONObject): Pair<JSONObject, String> {
        need(app)
        val w = Event.of(wrap)
        if (w.kind != 1059 || !verifyEvent(w)) no("not a vault invitation")
        d.ecdhX(w.pubkey)
        val seal = try { Event.of(Json.obj(d.nip44(w.pubkey, w.content, false))) } catch (_: Exception) { no("not a vault invitation") }
        if (seal.kind != 13 || !verifyEvent(seal)) no("not a vault invitation")
        d.ecdhX(seal.pubkey)
        val rj = try { Json.obj(d.nip44(seal.pubkey, seal.content, false)) } catch (_: Exception) { no("not a vault invitation") }
        val rumor = try { Event.shape(rj, "rumor") } catch (_: Exception) { no("not a vault invitation") }
        if (rumor.kind != Doors.KIND_VAULT_INVITE || rumor.pubkey != seal.pubkey || eventId(rumor) != rumor.id) no("not a vault invitation")
        return rj to seal.pubkey
    }

    /** NIP-44 as the account with `peer`, answered only when the plaintext is a vault payload. */
    fun decrypt(app: String, peer: String, payload: String): String {
        need(app)
        d.ecdhX(peer)
        val plain = try { d.nip44(peer, payload, false) } catch (_: Exception) { no("not a vault payload") }
        if (!Doors.vaultPayload(plain)) no("not a vault payload")
        return plain
    }
}
