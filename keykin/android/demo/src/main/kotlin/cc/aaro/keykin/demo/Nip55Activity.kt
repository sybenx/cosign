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
        val line = TextView(this).apply { text = r.describe(); textSize = 18f }
        col.addView(line)
        // The scope this needs, worked out here in the signer process, so the words say what is really asked.
        // An event Device policy would put on a Confirm card says why (the tap here is that Confirm).
        Thread { val d = Memberships.signer(Memberships.slotFor(r.current)!!).device; val sc = d?.let { Nip55.scopeNeeded(it, r) }
            val why = if (d != null && r.type == "sign_event") r.caller?.let { Memberships.grantFor(it, r.current) }?.let { Nip55.verdict(d, r.payload, "${d.pub}:${it.id}") }?.takeIf { it.level != "silent" }?.reason else null
            runOnUiThread { line.text = r.describe(sc, why) } }.start()
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
