// NIP-46 at its home (Doors §3.3) for the Kotlin device, ported from the TS reference's device/nip46.ts
// with review 11's fixes: per-site signer keys that never leave the device, bunker:// links bound to the
// first client and dead after 10 minutes, nostrconnect:// codes, the methods and their errors, the
// machinery guard and no decryption of the account's own data (device/doors.ts), requests only within
// 2 minutes and each once, held events kept for the person and approved by the lock or a hold, and the wake path
// (watch_set to one watching server, whose kept requests arrive with each catch-up). Its state (signer keys
// included) is a part of the device's sealed snapshot, as TS keeps it.
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.security.SecureRandom

class Nip46Home(private val d: Device, private val net: RelayNet, private val secp: Secp = Keykin.secp) {
    /** `entry`: the grant store's entry once a client is bound (Doors §1); `offered`: the scopes the link offered. */
    class Grant(val signer: String, val signerSk: ByteArray, var client: String?, val secret: String?, var linkExpires: Long?, val relays: List<String>, var endedAt: Long? = null,
                var entry: String? = null, val offered: List<String> = listOf("sign-in", "post"), val site: String = "", var connectedAt: Long? = null)
    class Held(val id: String, val signer: String, val event: Unsigned, val at: Long, var wait: String? = null, val reason: String = "")
    /** The server this home asked to watch for it (one per account), and whether a watch_set is still to send. */
    @Volatile var watching: String? = null; private set
    @Volatile var watchPending = false; private set
    val grants = LinkedHashMap<String, Grant>()
    val held = LinkedHashMap<String, Held>()
    /** Scopes sites asked for that the person hasn't answered, by signer (Doors §1: asked the first time). */
    val asks = LinkedHashMap<String, MutableSet<String>>()
    // Locking: the home's maps change only under its own lock, and nothing saves (which takes the device's lock, whose
    // snapshot then takes this one's) while holding it (review 20 H1, M5).
    /** Shown to the app: a held event or a scope ask came or went. */
    @Volatile var onChange: (() -> Unit)? = null
    private fun changed() { try { onChange?.invoke() } catch (_: Exception) {} }
    private fun grant(signer: String?): Grant? = synchronized(this) { signer?.let { grants[it] } }
    fun allowScope(signer: String, scope: String) {
        val g = grant(signer) ?: refuse("unknown_grant")
        d.grants.widen(g.entry ?: refuse("unknown_grant"), listOf(scope))
        synchronized(this) { asks[signer]?.remove(scope) }
        d.publishGrantsSoon(); changed()
    }
    private fun bind(g: Grant, client: String) {
        g.client = client; g.connectedAt = net.now
        g.entry = d.grants.make(client, g.site, "nip46", client, g.offered, g.relays, g.signer).getString("id")
        d.publishGrantsSoon()
        // A watching server keeps this site's requests while the phone sleeps, and pushes (Doors §3.3).
        try { watchSet() } catch (_: Exception) { watchPending = true }
        d.saveNow()
    }
    /** Ask the watching server to watch this home's live grants (an empty set stops it). */
    fun watchSet() {
        // One watching server, re-picked when it no longer holds a seat (review 20 L15).
        if (watching == null || d.servers().none { it.key == watching }) watching = d.servers().firstOrNull()?.key
        val server = watching ?: return
        val gs = JSONArray(synchronized(this) { grants.values.filter { it.endedAt == null }.map { JSONObject().put("signer", it.signer).put("client", it.client ?: JSONObject.NULL).put("relays", JSONArray(it.relays)) } })
        val a = d.send(server, d.msg("watch_set", "ask").put("grants", gs))
        if (a.optString("type") != "ack") { watchPending = true; refuse(a.optString("code").ifEmpty { "watch_set_failed" }) }
        watchPending = false; d.saveNow()
    }
    /** Woken (a push, or the app opened): a pending watch_set first, then a catch-up, which also hands this home
     *  every site request the watching server kept. */
    fun wake() { if (watchPending) try { watchSet() } catch (_: Exception) {}; d.fetch() }
    private fun has(g: Grant, scope: String): Boolean {
        val e = g.entry?.let { d.grants.own[it] }
        // An expired grant grants nothing (review 16 M4).
        if (e != null && scope in d.grants.scopesOf(e) && !Grants.expired(e, net.now, null)) { d.grants.used(e.getString("id")); return true }
        // The ask is kept, and the app told (review 20 L16, M9).
        val fresh = synchronized(this) { asks.getOrPut(g.signer) { LinkedHashSet() }.add(scope) }
        if (fresh) { d.saveNow(); changed() }
        return false
    }
    private fun ask(scope: String) = err("permission: $scope needs your OK on your phone")
    private val crypt = HashMap<String, ArrayDeque<Long>>()
    @Synchronized private fun budget(signer: String): Boolean {
        val q = crypt.getOrPut(signer) { ArrayDeque() }; while (q.isNotEmpty() && net.now - q.first() > 3600) q.removeFirst()
        if (q.size >= 300) return false; q.addLast(net.now); return true
    }
    private val seen = LinkedHashMap<String, Long>()
    private var stop: (() -> Unit)? = null
    private val env = Envelope(secp)
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "keykin-nip46").also { it.isDaemon = true } }
    private fun rand(n: Int) = ByteArray(n).also { SecureRandom().nextBytes(it) }
    private fun key(): ByteArray = rand(32).also { it[0] = (it[0].toInt() and 0x7f).toByte() }

    init {
        load(d.carriedPart("nip46"))
        d.snapshotParts["nip46"] = { dump() }
        // A wiped or removed device's home goes with it: no grant, held event or signer key stays (review 13 M6).
        d.onGone { sleep(); synchronized(this) { grants.values.forEach { it.signerSk.fill(0) }; grants.clear(); held.clear() } }
        // A grant ended on this device or elsewhere (a delivered end, sign out of every site): its site is revoked here.
        d.onEnds { ids ->
            val any = synchronized(this) { grants.values.filter { it.endedAt == null && it.entry in ids }.onEach { it.endedAt = net.now; asks.remove(it.signer); held.entries.removeIf { h -> h.value.signer == it.signer } }.isNotEmpty() }
            // The watching server stops watching it too (review 20 L15).
            if (any) { try { watchSet() } catch (_: Exception) {}; changed() }
        }
        // Sites' requests a watching server kept for this device come here, answered before they are acked (review 11
        // M1, review 20 M6).
        d.onSiteRequest = { e -> try { handle(e) } catch (_: Exception) {} }
    }
    fun mintBunker(relays: List<String>, site: String = "", scopes: List<String> = listOf("sign-in", "post")): String {
        val sk = key(); val g = Grant(secp.pub(sk), sk, null, hex(rand(16)), net.now + 600, relays, offered = scopes, site = site)
        synchronized(this) { grants[g.signer] = g }; listen(); d.saveNow()
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
        synchronized(this) { grants[g.signer] = g }; bind(g, client); listen()
        reply(g, client, JSONObject().put("id", hex(rand(8))).put("result", q.firstOrNull { it.first == "secret" }?.second ?: "ack"), false)
        return g
    }
    fun listen() {
        stop?.invoke()
        // A link never used goes once it expires; an ended grant 30 days after its end, its `revoked:` said (M12).
        val live = synchronized(this) {
            grants.entries.removeIf { (_, g) -> (g.client == null && g.linkExpires != null && net.now > g.linkExpires!!) || (g.endedAt != null && net.now - g.endedAt!! > 30 * 86400) }
            grants.values.toList()
        }
        // Off the relay's listener thread: answering signs, and the co-signer's answer arrives on that thread.
        // On the grants' own relays too, dialled when not yet (review 11 H3).
        stop = if (live.isEmpty()) null else net.watch(JSONObject().put("kinds", JSONArray(listOf(24133))).put("#p", JSONArray(live.map { it.signer })), { e -> worker.execute { try { handle(e) } catch (_: Exception) {} } }, live.flatMap { it.relays }.distinct())
    }
    fun sleep() { stop?.invoke(); stop = null }

    /** One request from a site; false when there was nothing to answer. */
    fun handle(e: JSONObject): Boolean {
        if (d.wiped) return false
        val ev = Event.of(Json.obj(e.toString()))
        if (ev.kind != 24133 || Math.abs(net.now - ev.createdAt) > 120 || !verifyEvent(ev)) return false
        // Each request once, remembered across a restart (review 20 M7).
        if (!synchronized(this) { seen.entries.removeIf { net.now - it.value > 120 }; seen.putIfAbsent(ev.id, ev.createdAt) == null }) return false
        val g = grant(ev.tag("p")) ?: return false
        var nip04 = false
        val req = try { Json.obj(Nip44.decrypt(ev.content, Nip44.conversationKey(secp, g.signerSk, ev.pubkey))) }
            catch (_: KeykinException) { try { nip04 = true; Json.obj(nip04Decrypt(g.signerSk, ev.pubkey, ev.content)) } catch (_: Exception) { return false } }
        val id = req.opt("id") as? String ?: return false
        val method = req.opt("method") as? String ?: return false
        val params = req.optJSONArray("params")?.let { a -> (0 until a.length()).map { a.get(it).toString() } } ?: emptyList()
        // Too few params, or any other fault, still gets an answer (review 20 L17).
        val ans = try { answer(g, ev.pubkey, method, params) } catch (_: IndexOutOfBoundsException) { err("declined: missing params") } catch (_: Exception) { err("declined: refused") }
        reply(g, ev.pubkey, ans.put("id", id), nip04)
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
                    // Device policy §2: judged first. A Confirm waits for the person's answer on this home, a single
                    // deletion 10 seconds for an Undo; Held goes to the person at once.
                    val owner = "${d.pub}:${g.entry}"
                    val event = Unsigned(d.g, at, kind, tags, content)
                    // Device policy §4: while a hold for this list is pending, site changes to it wait (review 20 L14).
                    val lk = if (Rules.replaceable(kind)) Kinds.addrOf(kind, tags) else null
                    if (lk != null && synchronized(this) { held.values.any { it.wait != null && Rules.replaceable(it.event.kind) && Kinds.addrOf(it.event.kind, it.event.tags) == lk } }) return err("try-later: a held change to this list is waiting")
                    var reason = "two servers asked for an approval"
                    // A site's deletions and list changes are judged and signed one at a time (review 18 M1). Signed
                    // for this grant: the evidence records who got each ciphertext signed (review 17 M1).
                    try {
                        val (gate, signed) = d.guard.serve(event, owner, g.entry?.let { d.grants.own[it] }?.let { d.grants.scopesOf(it).toList() } ?: emptyList()) { d.sign(kind, content, tags, at, owner) }
                        gate.error?.let { return err(it) }
                        if (signed != null) return ok(signed.toString())
                        reason = gate.verdict.reason
                    } catch (e: KeykinException) {
                        if (e.code != "needs_approval") throw e
                        // A server's demand the device's own check doesn't explain: Held only when two servers demand it.
                        if (e.demands < 2) return err("try-later: a server asked for an approval; try again later")
                    }
                    // One per event, at most 8 per site and 64 in all (review 12 H2).
                    synchronized(this) {
                        held.entries.removeIf { net.now - it.value.at > 7 * 86400 }
                        if (held.values.none { it.event.id == event.id }) {
                            if (held.values.count { it.signer == g.signer } >= 8 || held.size >= 64) return err("try-later: too many events waiting for you")
                            val h = Held(event.id, g.signer, event, net.now, reason = reason); held[h.id] = h
                        }
                    }
                    d.saveNow(); changed()
                    err("held: approve on your phone")
                }
                // Encrypting to the account's own key is `post`, to anyone else `dms`; decrypting with others is `dms`,
                // to the account itself released only under the scope its plaintext needs (Doors §1).
                "nip44_encrypt", "nip04_encrypt" -> {
                    val need = if (params[0].lowercase() == d.g) "post" else "dms"; if (!has(g, need)) return ask(need)
                    // At most 300 encryptions to self an hour per site: each becomes a metadata record (review 17 H2).
                    if (need == "post" && !budget(g.signer)) return err("try-later: too many encryptions; wait a while")
                    // An encryption to self is recorded for this grant: evidence for its later decrypts.
                    // Doors 20 §2: never a vault invitation or vault payload encrypted for a site.
                    if (Doors.vaultPlaintext(params[1])) return err("declined: vault material is the vault apps' own")
                    ok(if (method == "nip44_encrypt") d.nip44(params[0], params[1], true, "${d.pub}:${g.entry}") else d.nip04(params[0], params[1], true))
                }
                "nip44_decrypt", "nip04_decrypt" -> {
                    if (!Regex("^[0-9a-fA-F]{64}$").matches(params[0])) refuse("declined", "a peer key is 32 bytes of hex")
                    val peer = params[0].lowercase()
                    if (peer != d.g) {
                        if (!has(g, "dms")) return ask("dms")
                        val text = if (method == "nip44_decrypt") d.nip44(peer, params[1], false) else d.nip04(peer, params[1], false)
                        // Doors 20 §2: never vault material to a site, under any scope.
                        return if (Doors.vaultPlaintext(text)) err("declined: vault material reaches a site only through the vault API") else ok(text)
                    }
                    // To self: a grant with no to-self scope is refused before any round; then the scope the bytes'
                    // evidence and plaintext need, checked whatever it is (review 16 M1, M9), one message for every class.
                    val e = g.entry?.let { d.grants.own[it] }
                    if (e == null || d.grants.scopesOf(e).none { it in setOf("lists", "wallet", "private-data", "dms") }) { has(g, "private-data"); return err("permission: needs your OK on your phone") }
                    val plain = if (method == "nip44_decrypt") d.nip44(peer, params[1], false) else d.nip04(peer, params[1], false)
                    val need = Grants.scopeForDecrypt(d.g, peer, plain, if (method == "nip44_decrypt") params[1] else null, d.evidence, "${d.pub}:${g.entry}")
                    if (need == "malformed") return err("declined: not a canonical payload")
                    if (!has(g, need)) return err("permission: needs your OK on your phone")
                    if (Doors.vaultPlaintext(plain)) return err("declined: vault material reaches a site only through the vault API")
                    ok(plain)
                }
                else -> err("unsupported: $method")
            }
        } catch (e: KeykinException) {
            when (e.code) {
                "declined" -> err("declined: " + (e.message ?: "").removePrefix("declined: "))
                "needs_approval", "hold_not_passed" -> err("held: approve on your phone")
                "unreachable", "no_server", "no_answer" -> err("try-later: no server answered")
                else -> err("declined: ${e.code}")
            }
        }
    }
    private fun siteGuard(kind: Int, tags: List<List<String>>) = Doors.siteGuard(d, kind, tags)
    /** End a grant here: its key answers `revoked:` from now on, and its entry ends in the grant store. */
    private fun end(g: Grant) {
        g.endedAt = net.now; g.entry?.let { d.grants.end(d.pub, it); d.publishGrantsSoon() }; asks.remove(g.signer); held.entries.removeIf { it.value.signer == g.signer }
        try { watchSet() } catch (_: Exception) {}
        d.saveNow()
    }

    // --- held events (Doors §3.3, Device policy §4) ----------------------------------------------
    /** A held event of a live grant, or refused; one a newer version of its list overtook is dropped. */
    /** A held event of a live grant, after a catch-up (a site signed out elsewhere, an expiry, a newer version of its
     *  list all drop it: review 20 M8, Device policy §4). */
    private fun heldLive(id: String): Held {
        if (net.now - d.lastFetchAt > 30) try { d.fetch() } catch (_: Exception) {}
        val h = synchronized(this) { held[id] } ?: refuse("unknown_held")
        val g = grant(h.signer)
        val e = g?.entry?.let { d.grants.own[it] }
        val drop = when {
            g == null || g.endedAt != null || (g.entry != null && (e == null || Grants.expired(e, net.now, null))) -> "revoked"
            else -> { val a = if (Rules.replaceable(h.event.kind)) Kinds.addrOf(h.event.kind, h.event.tags) else null
                val newer = a?.let { d.history.current(it) }; if (newer != null && newer.createdAt > h.event.createdAt) "superseded" else null }
        }
        if (drop != null) {
            synchronized(this) { held.remove(id) }
            if (drop == "superseded") d.notices += JSONObject().put("kind", "held_dropped").put("member", h.signer)
            d.saveNow(); changed()
            if (drop == "revoked") refuse("revoked", "the site was disconnected") else refuse("superseded", "the list changed since: the held change was dropped")
        }
        return h
    }
    private fun ownerOf(signer: String) = "${d.pub}:${grants[signer]?.entry}"
    /** Held events waiting for the person: {id, signer, site, kind, content (the first 200 characters), at, wait}. */
    @Synchronized fun heldList(): JSONArray = JSONArray(held.values.map { h -> JSONObject().put("id", h.id).put("signer", h.signer)
        .put("site", grants[h.signer]?.let { g -> g.site.ifEmpty { g.entry?.let { d.grants.own[it]?.optString("says") } ?: "" } } ?: "")
        // What it does, in the judge's words, and its tags too, so the person sees what changes (review 20 L13).
        .put("reason", h.reason).put("kind", h.event.kind).put("tags", h.event.tags.size).put("content", h.event.content.take(200)).put("at", h.at).put("wait", h.wait ?: JSONObject.NULL) })
    /** Sign a held event unchanged with the lock's approval (`{"lock": {member, assertion}}` over "sign" ‖ event id),
     *  and publish it to the site's relays and the account's. */
    fun approveHeld(id: String, approval: JSONObject): JSONObject {
        val h = heldLive(id); val e = h.event
        val signed = d.sign(e.kind, e.content, e.tags, e.createdAt, ownerOf(h.signer), JSONObject().put("approval", approval))
        publishHeld(h, signed); return signed
    }
    /** Lockless: start a hold at every server (core §5.8); `releaseHeld` once its wait has passed. */
    fun holdHeld(id: String): String {
        // The hold is for a device with no lock; with one, the lock approves (Device policy §2, review 20 M4). At most
        // one pending hold per site.
        if (d.lock != null) refuse("has_lock", "this device has a lock: approve with it")
        val h = heldLive(id)
        if (synchronized(this) { held.values.any { it !== h && it.signer == h.signer && it.wait != null } }) refuse("try_later", "a hold for this site is already waiting")
        var wait: String? = null
        for (s in d.servers()) try { val a = d.send(s.key, d.msg("hold", "member").put("event", h.event.wire())); if (a.optString("kind") == "hold") wait = a.optString("wait").ifEmpty { wait } } catch (_: Exception) {}
        synchronized(this) { h.wait = wait ?: refuse("no_server", "no server started the hold") }; d.saveNow(); changed()
        return h.wait!!
    }
    fun releaseHeld(id: String): JSONObject {
        val h = heldLive(id); val wait = h.wait ?: refuse("unknown_held", "no hold was started"); val e = h.event
        val signed = d.sign(e.kind, e.content, e.tags, e.createdAt, ownerOf(h.signer), JSONObject().put("hold", wait))
        publishHeld(h, signed); return signed
    }
    /** The person declined it: a decline of that site (Device policy §6). */
    fun declineHeld(id: String) { val h = synchronized(this) { held.remove(id) } ?: return; d.guard.declined(ownerOf(h.signer), "core"); d.saveNow(); changed() }
    private fun publishHeld(h: Held, signed: JSONObject) {
        net.publishEventTo(signed, (grants[h.signer]?.relays ?: emptyList()) + d.recordRelays())
        synchronized(this) { held.remove(h.id) }; d.saveNow(); changed()
    }

    // --- durable state, as TS's dump: signer keys go with the device's sealed snapshot -------------------------
    @Synchronized fun dump(): JSONObject = JSONObject()
        .put("grants", JSONArray(grants.values.map { g -> JSONObject().put("signer", g.signer).put("signerSk", hex(g.signerSk)).put("client", g.client ?: JSONObject.NULL)
            .put("secret", g.secret ?: JSONObject.NULL).put("linkExpires", g.linkExpires ?: JSONObject.NULL).put("relays", JSONArray(g.relays)).put("site", g.site)
            .put("connectedAt", g.connectedAt ?: JSONObject.NULL).put("endedAt", g.endedAt ?: JSONObject.NULL).put("entry", g.entry ?: JSONObject.NULL).put("offered", JSONArray(g.offered)) }))
        .put("watching", watching ?: JSONObject.NULL).put("watchPending", watchPending)
        .put("held", JSONArray(held.values.map { h -> JSONObject().put("id", h.id).put("signer", h.signer).put("event", h.event.wire()).put("at", h.at).put("wait", h.wait ?: JSONObject.NULL).put("reason", h.reason) }))
        .put("asks", JSONArray(asks.map { (k, v) -> JSONArray(listOf(k, JSONArray(v.toList()))) }))
        .put("seen", JSONArray(seen.map { (k, v) -> JSONArray(listOf(k, v)) }))
    @Synchronized private fun load(x: JSONObject?) {
        if (x == null) return
        fun str(o: JSONObject, k: String) = (o.opt(k) as? String)
        fun num(o: JSONObject, k: String) = (o.opt(k) as? Number)?.toLong()
        fun strs(a: JSONArray?) = a?.let { l -> (0 until l.length()).mapNotNull { l.opt(it) as? String } } ?: emptyList()
        x.optJSONArray("grants")?.let { a -> for (i in 0 until a.length()) a.optJSONObject(i)?.let { o ->
            val signer = str(o, "signer") ?: return@let; val sk = str(o, "signerSk") ?: return@let
            grants[signer] = Grant(signer, unhex(sk), str(o, "client"), str(o, "secret"), num(o, "linkExpires"), strs(o.optJSONArray("relays")), num(o, "endedAt"), str(o, "entry"),
                strs(o.optJSONArray("offered")).ifEmpty { listOf("sign-in", "post") }, str(o, "site") ?: "", num(o, "connectedAt")) } }
        watching = str(x, "watching"); watchPending = x.optBoolean("watchPending")
        x.optJSONArray("held")?.let { a -> for (i in 0 until a.length()) a.optJSONObject(i)?.let { o -> val e = o.optJSONObject("event") ?: return@let
            val tags = e.optJSONArray("tags")?.let { t -> (0 until t.length()).map { k -> strs(t.optJSONArray(k)) } } ?: emptyList()
            val u = Unsigned(e.optString("pubkey"), e.optLong("created_at"), e.optInt("kind"), tags, e.optString("content"))
            held[o.optString("id")] = Held(o.optString("id"), o.optString("signer"), u, o.optLong("at"), str(o, "wait"), o.optString("reason")) } }
        x.optJSONArray("seen")?.let { a -> for (i in 0 until a.length()) a.optJSONArray(i)?.let { p -> (p.opt(1) as? Number)?.let { seen[p.getString(0)] = it.toLong() } } }
        x.optJSONArray("asks")?.let { a -> for (i in 0 until a.length()) a.optJSONArray(i)?.let { p -> asks[p.getString(0)] = strs(p.optJSONArray(1)).toMutableSet() } }
        if (grants.values.any { it.endedAt == null }) listen()
    }

    private fun reply(g: Grant, to: String, body: JSONObject, nip04: Boolean) {
        val text = body.toString()
        val content = if (nip04) nip04Encrypt(g.signerSk, to, text) else Nip44.encrypt(text, Nip44.conversationKey(secp, g.signerSk, to))
        net.publishEventTo(env.sign(g.signerSk, 24133, net.now, listOf(listOf("p", to)), content), g.relays)
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
