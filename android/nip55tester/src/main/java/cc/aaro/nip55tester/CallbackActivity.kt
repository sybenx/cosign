package cc.aaro.nip55tester

import android.app.Activity
import android.os.Bundle
import android.util.Log

/** Where a "web page" (https://nip55.test/…) gets Cosign's answer: logged under NIP55TEST, then gone. */
class CallbackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i("NIP55TEST", "callback: ${intent.dataString}")
        finish()
    }
}
