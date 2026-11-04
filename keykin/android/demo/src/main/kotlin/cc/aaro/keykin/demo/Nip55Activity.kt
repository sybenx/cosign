// The demo's `nostrsigner:` screen (NIP-55), in the signer process: says which app wants what, and answers with
// keykin-android's Nip55 once the person taps; "Always" lets that app ask that again without the screen.
package cc.aaro.keykin.demo

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView
import keykin.android.Memberships
import keykin.android.Nip55

class Nip55Activity : Activity() {
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Memberships.init(this)
        val r = Nip55.parse(intent, callingPackage) ?: return Nip55.deny(this)
        if (Memberships.slotFor(r.current) == null) return Nip55.deny(this, r)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 96, 48, 48) }
        col.addView(TextView(this).apply { text = r.describe(); textSize = 18f })
        val always = CheckBox(this).apply { text = "Always allow this" }
        col.addView(always)
        var answered = false
        // Taps through an overlay don't count, and one tap answers once.
        col.addView(Button(this).apply { text = "Allow"; filterTouchesWhenObscured = true
            setOnClickListener { if (!answered) { answered = true; isEnabled = false; Thread { Nip55.approve(this@Nip55Activity, r, always.isChecked) }.start() } } })
        col.addView(Button(this).apply { text = "Deny"; filterTouchesWhenObscured = true; setOnClickListener { if (!answered) { answered = true; Nip55.deny(this@Nip55Activity, r) } } })
        setContentView(col)
    }
}
