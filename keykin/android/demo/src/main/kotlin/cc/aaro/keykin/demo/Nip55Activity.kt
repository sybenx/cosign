// The demo's `nostrsigner:` screen (NIP-55), in the signer process: says which app wants what, and answers
// with keykin-android's Nip55 once the person taps.
package cc.aaro.keykin.demo

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import keykin.android.Memberships
import keykin.android.Nip55

class Nip55Activity : Activity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Memberships.init(this)
        val r = Nip55.parse(intent, callingPackage) ?: return Nip55.deny(this)
        val slot = Memberships.slots().firstOrNull() ?: return Nip55.deny(this)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 96, 48, 48) }
        col.addView(TextView(this).apply { text = r.describe(); textSize = 18f })
        col.addView(Button(this).apply { text = "Allow"; setOnClickListener { Thread { Nip55.approve(this@Nip55Activity, r, slot) }.start() } })
        col.addView(Button(this).apply { text = "Deny"; setOnClickListener { Nip55.deny(this@Nip55Activity) } })
        setContentView(col)
    }
}
