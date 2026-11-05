// Debug builds only: grant a package NIP-55 access without the screen, so a test can query the provider from
// `adb shell content query` (as com.android.shell). Never in a release build: it would let anything grant itself.
package cc.aaro.keykin.demo

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import keykin.android.Memberships

class DebugGrant : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        Memberships.init(c)
        val slot = Memberships.slots().firstOrNull()
        val pkg = i.getStringExtra("pkg") ?: return
        val scopes = (i.getStringExtra("scopes") ?: "sign-in").split(",").filter { it.isNotBlank() }
        val g = slot?.let { Memberships.grant(it, pkg, pkg, scopes) }
        Log.i("KeykinDemo", """{"granted":${g != null}}""")
    }
}
