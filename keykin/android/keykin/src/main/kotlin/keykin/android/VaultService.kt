// The door for vault apps on the same phone (Doors 20 §3.7, IKeykinVaults.aidl): exported from the signer process.
// The app is who Android says is calling: its one package for the calling uid, and its signing certificate (the
// original one of a rotated key, so a rotation keeps the grant), so an app reinstalled under the same name by someone
// else is a different app. A grant whose package is gone or re-signed is dropped (KeykinService.stateOf). Nothing is answered until the person
// granted that app all three open vault domains on VaultGrantActivity, one question for the set; then only the
// vault calls (keykin.VaultCalls), each on its own thread so a slow server never blocks the binder pool long.
package keykin.android

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import keykin.Device
import keykin.KeykinException
import keykin.hex
import keykin.sha
import keykin.unhex
import android.net.Uri
import java.security.SecureRandom
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class VaultService : Service() {
    companion object {
        /** The app id a grant names: the package and a hash of its signing certificate (the original of a rotated
         *  key; every signer, sorted, for an app with several), or null when the uid isn't exactly one installed
         *  package (a shared uid is never a vault app). */
        fun appOf(c: Context, uid: Int): String? {
            val pkgs = c.packageManager.getPackagesForUid(uid) ?: return null
            if (pkgs.size != 1) return null
            val info = try { c.packageManager.getPackageInfo(pkgs[0], PackageManager.GET_SIGNING_CERTIFICATES) } catch (_: Exception) { return null }
            val si = info.signingInfo ?: return null
            val certs = if (si.hasMultipleSigners()) si.apkContentsSigners.map { sha(it.toByteArray()) }.sortedBy { hex(it) }
                else listOfNotNull(si.signingCertificateHistory?.firstOrNull()?.toByteArray())
            if (certs.isEmpty()) return null
            return appId(pkgs[0], certs.reduce { a, b -> a + b })
        }
        fun appId(pkg: String, cert: ByteArray) = "$pkg@" + hex(sha(cert)).take(32)
        /** A call's answer: {"result": …} or {"error": "<code>: <why>"}; never a stack trace or a key. */
        fun answer(f: () -> Any?): String = try { JSONObject().put("result", f() ?: JSONObject.NULL).toString() }
            catch (e: KeykinException) { JSONObject().put("error", e.message ?: e.code).toString() }
            catch (e: Exception) { JSONObject().put("error", "internal: the call failed").toString() }
        private const val SECONDS = 150L
    }
    private val calls = Executors.newCachedThreadPool { r -> Thread(r, "keykin-vault").also { it.isDaemon = true } }
    private val rnd = SecureRandom()

    override fun onCreate() { super.onCreate(); Proc.signerOnly("VaultService"); Memberships.init(this) }
    override fun onDestroy() { calls.shutdown(); super.onDestroy() }
    override fun onBind(intent: Intent?): IBinder = binder

    private fun devices(account: String): List<Device> = Memberships.slots().mapNotNull { s -> try { Memberships.signer(s).device } catch (_: Exception) { null } }
        .filter { it.g == account && !it.wiped }
    /** The device for `account` that granted `app`. The same answer whether the account isn't here or the app isn't
     *  granted, so an app without a grant can't learn which accounts this phone holds (review 22 M5). */
    private fun device(account: String, app: String): Device =
        devices(account).firstOrNull { app in it.vault.allowed() } ?: throw KeykinException("declined", "this app hasn't been granted your vaults on this device")
    private fun call(f: (app: String) -> Any?): String {
        val app = appOf(this, Binder.getCallingUid()) ?: return JSONObject().put("error", "declined: the caller isn't one app").toString()
        val job = calls.submit<String> { answer { f(app) } }
        // A call past its time is cancelled: an event it was signing may still be signed, so the app reads before retrying.
        return try { job.get(SECONDS, TimeUnit.SECONDS) } catch (_: Exception) { job.cancel(true); JSONObject().put("error", "try-later: the call took too long").toString() }
    }
    private fun ids(json: String) = JSONArray(json).let { a -> (0 until a.length()).map { a.getString(it) } }
    private fun state(p: Pair<List<String>, String>) = JSONObject().put("ids", JSONArray(p.first)).put("state", p.second)

    private val binder = object : IKeykinVaults.Stub() {
        override fun accounts(): String = call { app -> JSONArray(Memberships.slots().mapNotNull { s -> Memberships.signer(s).device?.takeIf { !it.wiped && app in it.vault.allowed() }?.g }.distinct()) }
        override fun askGrant(account: String?): PendingIntent? {
            val app = appOf(this@VaultService, Binder.getCallingUid()) ?: return null
            // One account per question (review 22 M4); none for an app already granted or declined (L7).
            if (account.isNullOrEmpty()) return null
            val ds = Binder.clearCallingIdentity().let { t -> try { devices(account) } finally { Binder.restoreCallingIdentity(t) } }
            if (ds.isEmpty() || ds.none { it.vault.mayAsk(app) }) return null
            // A fresh, unique intent each time, used once (review 22 H1): no other app's call can match it and rewrite
            // the app it names. Only this process makes it, so that app is the one Android said was calling.
            val nonce = hex(ByteArray(16).also { rnd.nextBytes(it) })
            val i = Intent(this@VaultService, VaultGrantActivity::class.java).setData(Uri.parse("keykin-vault://grant/$nonce"))
                .putExtra(VaultGrantActivity.APP, app).putExtra(VaultGrantActivity.ACCOUNT, account).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            return Binder.clearCallingIdentity().let { t -> try { PendingIntent.getActivity(this@VaultService, 0, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT) } finally { Binder.restoreCallingIdentity(t) } }
        }
        override fun ksig(account: String, rootHex: String): String = call { app -> device(account, app).vault.ksig(app, unhex(rootHex)).let { (mk, sig) -> JSONObject().put("mk", mk).put("ksig", sig) } }
        override fun derive(account: String, idsJson: String, domain: String, bytesHex: String): String = call { app -> JSONObject().put("key", hex(device(account, app).vault.derive(app, ids(idsJson), domain, unhex(bytesHex)))) }
        override fun current(account: String): String = call { app -> state(device(account, app).vault.current(app)) }
        override fun states(account: String): String = call { app -> JSONArray(device(account, app).vault.states(app).map { state(it) }) }
        override fun sign(account: String, eventJson: String): String = call { app ->
            val e = JSONObject(eventJson); val d = device(account, app)
            val tags = e.optJSONArray("tags")?.let { a -> (0 until a.length()).map { k -> a.getJSONArray(k).let { t -> (0 until t.length()).map { t.getString(it) } } } } ?: emptyList()
            if (e.has("pubkey") && e.getString("pubkey") != d.g) throw KeykinException("malformed", "the event names another pubkey")
            d.vault.sign(app, e.getInt("kind"), e.optString("content"), tags, if (e.has("created_at")) e.getLong("created_at") else d.now)
        }
        override fun invite(account: String, rumorJson: String, recipient: String): String = call { app -> device(account, app).vault.invite(app, JSONObject(rumorJson), recipient) }
        override fun unwrap(account: String, wrapJson: String): String = call { app -> device(account, app).vault.unwrap(app, JSONObject(wrapJson)).let { (r, seal) -> JSONObject().put("rumor", r).put("seal", seal) } }
        override fun decrypt(account: String, peer: String, payload: String): String = call { app -> JSONObject().put("plain", device(account, app).vault.decrypt(app, peer, payload)) }
    }
}
