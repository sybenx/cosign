package cc.aaro.nip55tester

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Does what an Android Nostr app does with an external signer (NIP-55), one step after
 * another, and logs each result under the tag NIP55TEST:
 *
 *   connect → a note, quietly → a follow list, quietly → emptying it (needs you) →
 *   a message encrypted (first time: needs you) → decrypted quietly → NIP-04 both ways
 */
class TestActivity : ComponentActivity() {
    private val signer = "cc.aaro.cosign"
    private var me = ""
    private var steps = ArrayDeque<() -> Unit>()
    private var onResult: (Intent?) -> Unit = {}
    private val launcher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode != Activity.RESULT_OK) log("signer failed (result ${r.resultCode})")
        onResult(r.data)
    }
    private val peer = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" // the key of private key 1

    private fun log(s: String) = Log.i("NIP55TEST", s)
    private fun next() = runOnUiThread { steps.removeFirstOrNull()?.invoke() ?: log("DONE") }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val follows = (1..30).joinToString(",") { """["p","${"%064x".format(it)}"]""" }
        steps = ArrayDeque(listOf(
            { intent("get_public_key", "") { log("get_public_key: ${it?.getStringExtra("result")} package=${it?.getStringExtra("package")}"); me = it?.getStringExtra("result") ?: ""; next() } },
            { quietOrAsk("SIGN_EVENT", "sign_event", """{"kind":1,"content":"gm from the NIP-55 tester","tags":[],"created_at":${now()}}""", "") },
            { quietOrAsk("SIGN_EVENT", "sign_event", """{"kind":3,"content":"","tags":[$follows],"created_at":${now()}}""", "") },
            { quietOrAsk("SIGN_EVENT", "sign_event", """{"kind":3,"content":"","tags":[],"created_at":${now() + 1}}""", "") },
            { quietOrAsk("NIP44_ENCRYPT", "nip44_encrypt", "hello from the tester", peer) { ct -> steps.addFirst { quietOrAsk("NIP44_DECRYPT", "nip44_decrypt", ct, peer) } } },
            { quietOrAsk("NIP04_ENCRYPT", "nip04_encrypt", "nip04 hello", peer) { ct -> steps.addFirst { quietOrAsk("NIP04_DECRYPT", "nip04_decrypt", ct, peer) } } },
        ))
        next()
    }

    private fun now() = System.currentTimeMillis() / 1000

    /** The Content Resolver first, as apps do; if Cosign answers null, the Intent. */
    private fun quietOrAsk(authority: String, type: String, payload: String, pubkey: String, then: (String) -> Unit = {}) {
        Thread {
            val t = System.currentTimeMillis()
            val c = contentResolver.query(Uri.parse("content://$signer.$authority"), arrayOf(payload, pubkey, me), null, null, null)
            val quiet = c?.use { if (it.getColumnIndex("rejected") > -1 || !it.moveToFirst()) null else it.getString(it.getColumnIndex("result")) }
            val ms = System.currentTimeMillis() - t
            if (quiet != null) {
                log("$type quietly in $ms ms: ${quiet.take(80)}")
                then(quiet); next()
            } else {
                log("$type: no quiet answer ($ms ms), opening Cosign")
                runOnUiThread {
                    intent(type, payload, pubkey) { r ->
                        val res = r?.getStringExtra("result")
                        if (r?.getBooleanExtra("rejected", false) == true) log("$type: REJECTED")
                        else log("$type after asking: ${res?.take(80)}${r?.getStringExtra("event")?.let { " event=" + it.take(60) } ?: ""}")
                        res?.let(then); next()
                    }
                }
            }
        }.start()
    }


    private fun intent(type: String, payload: String, pubkey: String = "", done: (Intent?) -> Unit) {
        onResult = done
        val i = Intent(Intent.ACTION_VIEW, Uri.parse("nostrsigner:$payload")).apply {
            if (type != "get_public_key") `package` = signer
            putExtra("type", type)
            putExtra("id", type + now())
            if (pubkey.isNotEmpty()) putExtra("pubkey", pubkey)
            if (me.isNotEmpty()) putExtra("current_user", me)
        }
        launcher.launch(i)
    }
}
