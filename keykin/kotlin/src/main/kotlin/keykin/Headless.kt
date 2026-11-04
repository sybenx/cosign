// A headless Kotlin device, for cross-language tests (test/kotlin.e2e.test.ts): load a TS device's
// snapshot, run each command of a JSON list over the given relays, print one JSON line per result.
//   keykin.HeadlessKt <snapshot.json> <relay,relay> <commands.json>
//   commands: [{"cmd":"sign","content":"…"}, {"cmd":"nip44"|"nip04","peer":"<hex>","text":"…","encrypt":true}, {"cmd":"fetch"}, {"cmd":"members"}, {"cmd":"datakey"}]
package keykin

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

fun main(args: Array<String>) {
    // A test harness: the JDK's socket, and a TS snapshot's soft lock may be used (never in an app).
    Keykin.wire = JdkWire; Keykin.allowSoftLock = true
    val net = RelayNet(args[1].split(",")).connect()
    try {
        // The first argument is a TS device's snapshot, or `join:<invite code>` to join as a new device.
        val d = if (args[0].startsWith("join:")) Device.join(args[0].removePrefix("join:"), net, { println(JSONObject().put("check", it).toString()); System.out.flush() })
            else Device.fromSnapshot(File(args[0]).readText(), net).also { dev -> dev.persist = { File(args[0]).writeText(it) } }
        println(JSONObject().put("device", d.pub).toString()); System.out.flush()
        val cmds = JSONArray(File(args[2]).readText())
        var lastGrant = ""
        for (k in 0 until cmds.length()) {
            val c = cmds.getJSONObject(k).let { x -> if (x.optString("id") == "__ID__") JSONObject(x.toString()).put("id", lastGrant) else x }
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
