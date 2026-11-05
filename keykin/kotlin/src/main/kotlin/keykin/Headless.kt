// A headless Kotlin device, for cross-language tests (test/kotlin.e2e.test.ts): load a TS device's
// snapshot, run each command of a JSON list over the given relays, print one JSON line per result.
//   keykin.HeadlessKt <snapshot.json> <relay,relay> <commands.json>
//   With `-` for the commands, they are read one JSON object per line from stdin until it ends, so a test can drive
//   several devices in turn (test/dryrun.e2e.test.ts).
//   commands: [{"cmd":"sign","content":"…"}, {"cmd":"nip44"|"nip04","peer":"<hex>","text":"…","encrypt":true}, {"cmd":"fetch"}, {"cmd":"members"}, {"cmd":"datakey"}]
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

fun main(args: Array<String>) {
    // A test harness: the JDK's socket, and a TS snapshot's soft lock may be used (never in an app).
    Keykin.wire = JdkWire; Keykin.allowSoftLock = true
    val net = RelayNet(args[1].split(",")).connect()
    // Tests only: a clock off by KEYKIN_CLOCK_SKEW seconds; a joined device's state kept in KEYKIN_STATE, so a test can
    // kill the process and start it again from that file.
    System.getenv("KEYKIN_CLOCK_SKEW")?.toLongOrNull()?.let { net.skew = it }
    val stateFile = System.getenv("KEYKIN_STATE")?.let { File(it) }
    try {
        // The first argument is a TS device's snapshot, or `join:<invite code>` to join as a new device.
        val d = if (args[0].startsWith("join:")) Device.join(args[0].removePrefix("join:"), net, { println(JSONObject().put("check", it).toString()); System.out.flush() })
                .also { dev -> stateFile?.let { f -> dev.persist = { f.writeText(it) }; dev.saveNow() } }
            else Device.fromSnapshot(File(args[0]).readText(), net).also { dev -> dev.persist = { File(args[0]).writeText(it) } }
        println(JSONObject().put("device", d.pub).toString()); System.out.flush()
        val fromStdin = args[2] == "-"
        val cmds = if (fromStdin) JSONArray() else JSONArray(File(args[2]).readText())
        var lastGrant = ""
        var k = -1
        while (true) {
            k++
            val raw: JSONObject
            if (fromStdin) { val line = (readLine() ?: break).trim(); if (line.isEmpty()) continue; raw = JSONObject(line) }
            else if (k < cmds.length()) raw = cmds.getJSONObject(k) else break
            val c = raw.let { x -> if (x.optString("id") == "__ID__") JSONObject(x.toString()).put("id", lastGrant) else x }
            val out = try {
                when (c.getString("cmd")) {
                    "sign" -> d.sign(1, c.getString("content"))
                    // Catch up from every server (changes, then the inbox) and say where this device now is.
                    "fetch" -> { d.fetch(); JSONObject().put("state", d.ctx.state).put("ids", JSONArray(d.ids.sorted())) }
                    // Deal a list with this device's lock (§6.7.6): a plain redeal, or a device's removal with its redeal.
                    "redeal", "remove" -> {
                        val list = JSONArray()
                        if (c.getString("cmd") == "remove") list.put(JSONObject().put("remove", c.getString("key")))
                        list.put(JSONObject().put("redeal", JSONObject().put("dealer", d.pub)))
                        val signed = d.submit(list, d.approveLock(list))
                        JSONObject().put("events", JSONArray(signed.map { it.getString("id") })).put("state", d.ctx.state)
                    }
                    // Invite (§4.1): print the code, read the new device's 6 digits from stdin, add and welcome it.
                    "invite" -> {
                        println(JSONObject().put("invite", d.invite(args[1].split(","))).toString()); System.out.flush()
                        val typed = readLine()?.trim() ?: ""
                        if (d.inviter?.typed(typed) != true) JSONObject().put("error", "check_mismatch") else JSONObject().put("added", d.addInvited()).put("state", d.ctx.state)
                    }
                    // Be the push gateway too (a test stand-in for UnifiedPush): register an address per server and
                    // class on this port, then take pushes for `seconds`, printing each payload and the state it left.
                    "push" -> {
                        val got = java.util.concurrent.LinkedBlockingQueue<Pair<String, ByteArray>>()
                        val http = com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1", c.getInt("port")), 0)
                        http.createContext("/") { ex -> got.put("http://127.0.0.1:${c.getInt("port")}${ex.requestURI.path}" to ex.requestBody.readBytes()); ex.sendResponseHeaders(201, -1); ex.close() }
                        http.start()
                        val n = d.registerPush { _, _ -> "http://127.0.0.1:${c.getInt("port")}/${hex(ByteArray(16).also { java.security.SecureRandom().nextBytes(it) })}" }
                        println(JSONObject().put("registered", n).toString()); System.out.flush()
                        val end = System.currentTimeMillis() + c.optLong("seconds", 60) * 1000
                        var last = JSONObject().put("pushes", 0)
                        var count = 0
                        while (System.currentTimeMillis() < end) {
                            val (url, body) = got.poll(500, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                            val p = d.onPush(url, body) ?: continue
                            count++
                            if (!p.has("wrap")) d.fetch()
                            last = JSONObject().put("pushes", count).put("cls", p.optString("cls")).put("wrap", p.has("wrap")).put("state", d.ctx.state)
                            if (c.optString("until") == "state" && d.ids.isNotEmpty()) break
                        }
                        http.stop(0); last
                    }
                    // Pair (§6.2): ask device `with` to approve removing `key` with this one; print the code, wait for the
                    // person to type it there, then deal and submit the list with the pair approval.
                    "pair_remove" -> {
                        val list = JSONArray().put(JSONObject().put("remove", c.getString("key"))).put(JSONObject().put("redeal", JSONObject().put("dealer", d.pub)))
                        val (code, approval) = d.pairStart(list, c.getString("with"))
                        println(JSONObject().put("code", code).toString()); System.out.flush()
                        val a = approval.get(c.optLong("seconds", 120), java.util.concurrent.TimeUnit.SECONDS) ?: refuse("refused")
                        JSONObject().put("events", JSONArray(d.submit(list, a).map { it.getString("id") })).put("state", d.ctx.state)
                    }
                    "members" -> d.members.devices().let { (self, asOf, keys) -> JSONObject().put("self", self).put("asOf", asOf)
                        .put("keys", JSONArray(keys.map { JSONObject().put("key", it.key).put("added_by", it.addedBy ?: JSONObject.NULL).put("flagged", it.flagged) }))
                        .put("removed", JSONArray(d.members.removed(0).map { it.json() })) }
                    "datakey" -> d.dataKey().let { (st, k) -> JSONObject().put("state", st).put("key", hex(k)) }
                    // Core 14.21: an app's derived key at the current state, and how many seed-only items servers hold.
                    "derive" -> d.currentState().let { (ids, st) -> MemberSig.register(c.getString("domain"))   // as a vault app registers at load
 JSONObject().put("state", st).put("ids", JSONArray(ids)).put("key", hex(d.derive(ids, c.getString("domain"), utf8(c.getString("bytes"))))) }
                    // Doors 20 §3.7: the vault-app device calls, for app `app` (granted first by "vault_allow").
                    "vault_allow" -> { d.vault.allow(c.getString("app")); JSONObject().put("allowed", JSONArray(d.vault.allowed())) }
                    "vault_ksig" -> d.vault.ksig(c.getString("app"), unhex(c.getString("root"))).let { (mk, sig) -> JSONObject().put("mk", mk).put("ksig", sig) }
                    "vault_derive" -> d.vault.current(c.getString("app")).let { (ids, st) -> JSONObject().put("state", st).put("ids", JSONArray(ids)).put("key", hex(d.vault.derive(c.getString("app"), ids, c.getString("domain"), unhex(c.getString("bytes"))))) }
                    "vault_sign" -> d.vault.sign(c.getString("app"), c.getInt("kind"), c.optString("content"), c.optJSONArray("tags")?.let { a -> (0 until a.length()).map { k -> a.getJSONArray(k).let { t -> (0 until t.length()).map { t.getString(it) } } } } ?: emptyList())
                    "vault_invite" -> d.vault.invite(c.getString("app"), c.getJSONObject("rumor").put("pubkey", d.g).put("created_at", d.now), c.getString("to"))
                    "vault_unwrap" -> d.vault.unwrap(c.getString("app"), c.getJSONObject("wrap")).let { (r, seal) -> JSONObject().put("rumor", r).put("seal", seal) }
                    "vault_decrypt" -> JSONObject().put("plain", d.vault.decrypt(c.getString("app"), c.getString("peer"), c.getString("payload")))
                    // Report another device lost (§6.4), approved with this device's lock, or the paper's words on a lockless
                    // one, as keykin-android's Devices and paper does; the members afterwards.
                    "report_lost" -> {
                        val list = JSONArray().put(JSONObject().put("remove", c.getString("key"))).put(JSONObject().put("redeal", JSONObject().put("dealer", d.pub)))
                        val ap = if (d.lock != null) d.approveLock(list) else { val sk = Backup.readBackupWords(c.getString("words").trim().split(Regex("\\s+"))); try { d.approveWithPaper(list, sk) } finally { sk.fill(0) } }
                        d.submit(list, ap); JSONObject().put("devices", JSONArray(d.memberKeys())).put("wiped", d.wiped)
                    }
                    // The membership as this device sees it, without fetching (a Devices screen opened earlier).
                    // The other join direction: scan a new device's hello code, type its digits, approve the add with this
                    // device's lock or, lockless, the paper's words.
                    "invite_scanned" -> { d.inviteScanned(c.getString("code")); JSONObject().put("offered", true) }
                    "invite_typed" -> JSONObject().put("typed", d.inviter?.typed(c.getString("digits")) == true)
                    "add_invited" -> {
                        val list = d.inviteAddList()
                        val ap = if (list == null || d.lock != null) null else { val sk = Backup.readBackupWords(c.getString("words").trim().split(Regex("\\s+"))); try { d.approveWithPaper(list, sk) } finally { sk.fill(0) } }
                        JSONObject().put("added", d.addInvited(ap))
                    }
                    "devices" -> JSONObject().put("devices", JSONArray(d.memberKeys())).put("wiped", d.wiped)
                    "quit" -> break
                    "seeds" -> JSONObject().put("records", d.seedRecords().size).put("held", JSONArray(d.seedOnlyHeld()))
                    // Be a NIP-46 home (Doors §3.3): print a bunker:// link, then answer sites for `seconds`.
                    "bunker" -> { val home = d.nip46; println(JSONObject().put("bunker", home.mintBunker(args[1].split(","), "", c.optString("scopes", "sign-in,post").split(",").filter { it.isNotBlank() })).toString()); System.out.flush()
                        Thread.sleep(c.optLong("seconds", 30) * 1000); JSONObject().put("served", true) }
                    // Doors §2: make a grant and publish it; wait until an end made elsewhere drops it; sign out of every site.
                    "grant" -> { d.fetch(); val e = d.grants.make(c.getString("site"), c.getString("site"), "nip55", "pkg@1", listOf("sign-in", "post")); d.publishGrants()
                        lastGrant = e.getString("id"); JSONObject().put("grant", lastGrant).put("counted", d.grants.counted) }
                    "wait_ends" -> { val end = System.currentTimeMillis() + c.optLong("seconds", 60) * 1000
                        while (System.currentTimeMillis() < end && d.grants.own.containsKey(c.getString("id"))) { Thread.sleep(1000); try { d.fetch() } catch (_: Exception) {} }
                        JSONObject().put("ended", !d.grants.own.containsKey(c.getString("id"))) }
                    "signout_all" -> { d.signOutEverywhere(); JSONObject().put("own", d.grants.own.size) }
                    // Held events (core §5.8): the person approves each with this device's lock; or lets a hold's wait pass.
                    "approve_held" -> { val ids = d.nip46.heldList().let { a -> (0 until a.length()).map { a.getJSONObject(it).getString("id") } }
                        val lock = d.lock ?: refuse("no_lock")
                        JSONObject().put("approved", JSONArray(ids.map { id -> d.nip46.approveHeld(id, JSONObject().put("member", d.pub).put("assertion", lock.assert(d.g, Codes.whatSign(id))).let { JSONObject().put("lock", it) }).getString("id") })) }
                    "nip44" -> JSONObject().put("result", d.nip44(c.getString("peer"), c.getString("text"), c.optBoolean("encrypt", true)))
                    "nip04" -> JSONObject().put("result", d.nip04(c.getString("peer"), c.getString("text"), c.optBoolean("encrypt", true)))
                    else -> JSONObject().put("error", "unknown command")
                }
            } catch (e: KeykinException) { JSONObject().put("error", e.code).put("detail", e.message) } catch (e: Exception) { JSONObject().put("error", "internal").put("detail", e.toString()) }
            println(out.toString()); System.out.flush()
        }
    } catch (e: KeykinException) { println("""{"error":"${e.code}"}""") } finally { net.close() }
    System.exit(0)
}
