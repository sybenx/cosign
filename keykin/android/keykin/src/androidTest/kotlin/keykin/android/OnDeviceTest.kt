package keykin.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import keykin.Device
import keykin.Envelope
import keykin.Event
import keykin.KeykinException
import keykin.MemberSig
import keykin.Push
import keykin.RelayNet
import keykin.Upkeep
import keykin.checkAssertion
import keykin.hex
import keykin.scalarHex
import keykin.unhex
import keykin.utf8
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The shared Kotlin device on a real Android runtime: the TS reference's vectors, with Android's org.json,
 *  libsecp256k1 and the FROST library from the APK; and the Android parts (Keystore lock, sealed store). */
@RunWith(AndroidJUnit4::class)
class OnDeviceTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().context
    private fun asset(name: String) = JSONObject(ctx.assets.open(name).bufferedReader().readText())
    @Before fun start() { KeykinAndroid.init(); Proc.testProcess = true }

    @Test fun memberSigVectors() {
        val v = asset("membersig.json")
        val sk = unhex(v.getString("member_sk"))
        assertEquals(v.getString("member_key"), AndroidSecp.pub(sk))
        val valid = v.getJSONArray("valid")
        for (k in 0 until valid.length()) {
            val x = valid.getJSONObject(k); val msg = unhex(x.getString("message"))
            assertEquals(x.getString("digest"), hex(MemberSig.digest(x.getString("domain"), msg)))
            assertEquals(x.getString("sig"), MemberSig.sign(AndroidSecp, sk, x.getString("domain"), msg, ByteArray(32)))
        }
        val refused = v.getJSONArray("refused_domains")
        for (k in 0 until refused.length()) try { MemberSig.register(refused.getJSONObject(k).getString("domain")); fail() } catch (_: KeykinException) {}
    }

    @Test fun upkeepVectorsApplyAsInTs() {
        val v = asset("upkeep.json")
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        val steps = v.getJSONArray("steps")
        for (k in 0 until steps.length()) {
            val s = steps.getJSONObject(k); val after = s.getJSONObject("after")
            val dl = s.getJSONArray("deliveries"); for (i in 0 until dl.length()) d.takeDelivery(dl.getJSONObject(i))
            val ch = s.getJSONArray("changes"); d.takeChanges((0 until ch.length()).map { Event.of(ch.getJSONObject(it)) })
            assertEquals("step $k state", after.getString("state"), d.ctx.state)
            val sh = after.getJSONArray("shares")
            assertEquals((0 until sh.length()).associate { sh.getJSONArray(it).let { p -> p.getLong(0) to p.getString(1) } }, d.shares.mapValues { scalarHex(it.value) })
            assertEquals(after.getString("data_key"), hex(d.dataKey().second))
            val rm = after.getJSONArray("removed")
            assertEquals((0 until rm.length()).map { rm.getJSONObject(it).getString("key") }, d.members.removed(0).map { it.key })
            assertTrue(d.notices.toString(), d.notices.none { it.optString("kind") == "bad_backup_piece" || it.optString("kind") == "bad_delivery" })
        }
        assertTrue("every paper item verified from its eph", d.keptRedeals.isEmpty())
        // And the state survives a round trip through Android's org.json.
        val back = Device.fromSnapshot(d.snapshot(), RelayNet(emptyList()))
        assertEquals(d.ctx.state, back.ctx.state)
        assertEquals(hex(d.dataKey().second), hex(back.dataKey().second))
    }

    @Test fun aServersPushDecrypts() {
        val v = asset("push.json")
        val plain = Push.decrypt(unhex(v.getString("body")), unhex(v.getString("ua_sk")), unhex(v.getString("auth")))
        assertEquals(v.getString("plain"), hex(plain))
        assertEquals("ask", Push.read(plain, setOf(v.getString("host_key"))).getString("cls"))
    }

    @Test fun signsWithFrostFromTheApk() {
        // Two-of-four through the native library: the vector device signs nothing without a server, but its
        // shares and commitments go through the same calls a round makes.
        val v = asset("upkeep.json")
        val d = Device.fromSnapshot(v.getString("before"), RelayNet(emptyList()))
        val (i, s) = d.shares.entries.first()
        val c = keykin.Frost.commit(d.ctx.C, i, s, keykin.Frost.hedge(s, ByteArray(32)))
        assertEquals(66, c.d.length)
    }

    @Test fun aKeystoreLockSignsWhatTheReferenceChecks() {
        // A key without the biometric gate: an emulator test has no enrolled finger. The assertion's shape and
        // signature are what matter here; the gate is the Keystore's.
        val alias = "keykin-test-lock"
        KeystoreLock.destroy(alias)
        val lock = KeystoreLock.open(alias, requireBiometric = false)
        val g = "ab".repeat(32); val w = utf8("change") + ByteArray(56)
        assertNull(checkAssertion(g, lock.pub.getString("pub"), lock.pub.getString("rp"), w, lock.assert(g, w)))
        assertEquals("lock_challenge", checkAssertion(g, lock.pub.getString("pub"), lock.pub.getString("rp"), w + byteArrayOf(1), lock.assert(g, w)))
        KeystoreLock.destroy(alias)
    }

    @Test fun theSealedStoreKeepsStateAndForgetsIt() {
        val st = SealedStore(ctx, "test")
        st.save("""{"v":1,"secret":"x"}""")
        assertEquals("""{"v":1,"secret":"x"}""", st.load())
        assertTrue(java.io.File(ctx.noBackupFilesDir, "keykin-test.sealed").readBytes().toString(Charsets.ISO_8859_1).indexOf("secret") < 0)
        st.destroy()
        assertNull(st.load())
    }

    @Test fun androidJsonReadsWhatTheCoreWrites() {
        // Android's org.json differs from the desktop one (optString of a null is "null"; no keySet): the core's
        // own round trips must not depend on it.
        val o = JSONObject().put("a", JSONObject.NULL).put("b", JSONArray(listOf(1, 2)))
        assertEquals("{\"a\":null,\"b\":[1,2]}", keykin.Jcs.of(o))
        assertEquals(listOf("a", "b"), with(keykin.Json) { o }.let { x -> x.keys().asSequence().toList().sorted() })
        Envelope()   // with AndroidSecp underneath
    }

    @Test fun aPapersWordsReadAsInTs() {
        val v = asset("backup-words.json"); val ok = v.getJSONArray("valid")
        for (k in 0 until ok.length()) ok.getJSONObject(k).let { x ->
            val words = x.getJSONArray("words").let { a -> (0 until a.length()).map { a.getString(it) } }
            assertEquals(x.getString("secret"), hex(keykin.Backup.readBackupWords(words)))
        }
        val seed = v.getJSONArray("wallet_seed").let { a -> (0 until a.length()).map { a.getString(it) } }
        try { keykin.Backup.readBackupWords(seed); fail() } catch (e: KeykinException) { assertEquals("wallet_seed", e.code) }
    }

    @Test fun judgesEventsAsTs() {
        val v = asset("policy.json"); val g = v.getString("g"); val now = v.getLong("now"); val ck = unhex(v.getString("ck"))
        fun strs(a: JSONArray) = (0 until a.length()).map { a.getString(it) }
        val wrong = ArrayList<String>(); val cases = v.getJSONArray("cases")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val h = keykin.History { g }
            c.getJSONArray("history").let { a -> for (k in 0 until a.length()) h.take(Event.of(a.getJSONObject(k))) }
            val led = keykin.Ledger(); led.take(c.getJSONObject("ledger")) { true }
            val lookup = c.getJSONArray("lookup").let { a -> (0 until a.length()).map { Event.of(a.getJSONObject(it)) } }
            val e = c.getJSONObject("event"); val ta = e.getJSONArray("tags")
            val ev = keykin.Unsigned(e.getString("pubkey"), e.getLong("created_at"), e.getInt("kind"), (0 until ta.length()).map { strs(ta.getJSONArray(it)) }, e.getString("content"))
            val got = keykin.Policy.judge(ev, keykin.Policy.Ctx(g, now, c.getString("owner"), strs(c.getJSONArray("scopes")), h, led,
                { x -> try { keykin.Nip44.decrypt(x, ck) } catch (_: Exception) { null } }, { _, _ -> lookup }))
            if (got.level != c.getString("level") || got.row != c.getString("row")) wrong += "${c.getString("name")}: ${got.level}/${got.row}"
        }
        assertEquals(emptyList<String>(), wrong)
    }
}
