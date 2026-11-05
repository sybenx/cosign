// The demo's signer-process screen for what the person approves with the lock or the paper: report another device
// lost (core §6.7.6 F2: its remove and a redeal, approved with this phone's lock, or with the paper's 24 words on a
// lockless phone), and the paper check (are these words this account's paper?). The words never leave this process.
package cc.aaro.keykin.demo

import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import keykin.android.LockPrompt
import keykin.android.Memberships
import keykin.android.PaperEntry

class Tools : FragmentActivity() {
    private lateinit var line: TextView
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Memberships.init(this)
        val slot = intent.getStringExtra("slot") ?: return finish()
        val s = Memberships.signer(slot); val d = s.device ?: return finish()
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        line = TextView(this).apply { textSize = 16f; text = "This phone: ${d.pub.take(12)}…" }
        col.addView(line)
        val words = EditText(this).apply { hint = "the paper's 24 words"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS; minLines = 2 }
        fun typed() = words.text.toString().trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.also { words.setText("") }
        // Every other current device, with Report lost.
        for (k in d.view.devices.filter { it != d.pub && it !in d.view.removed }) col.addView(Button(this).apply {
            text = "Report ${k.take(12)}… lost"; filterTouchesWhenObscured = true
            setOnClickListener {
                val list = PaperEntry.removeList(slot, k)
                val lock = s.lock()
                if (lock != null) LockPrompt.approveList(this@Tools, d, lock, list, "Report a device lost", "${k.take(12)}… is removed from your account") { a, why ->
                    if (a == null) return@approveList say("not approved: $why")
                    Thread { try { d.submit(list, a); say("reported lost: ${k.take(12)}…") } catch (e: Exception) { say("failed: $e") } }.start()
                } else {
                    val w = typed(); if (w.size != 24) return@setOnClickListener say("a lockless phone approves with the paper: type its 24 words above first")
                    Thread { try { PaperEntry.submit(slot, list, w); say("reported lost with the paper: ${k.take(12)}…") } catch (e: Exception) { say("failed: $e") } }.start()
                }
            } })
        col.addView(words)
        col.addView(Button(this).apply { text = "Check the paper"; filterTouchesWhenObscured = true
            setOnClickListener { val w = typed(); Thread { say(try { if (PaperEntry.check(slot, w)) "the paper is this account's" else "these words are not this account's paper" } catch (e: Exception) { "failed: $e" }) }.start() } })
        setContentView(ScrollView(this).apply { addView(col) })
    }
    private fun say(x: String) = runOnUiThread { line.text = x }
}
