// The library's own screen for what the person approves (core §6.1–§6.4): report a device lost, check the paper, add
// an invited device, approve another device's pair request, and remove a device with a pair. It runs in the signer
// process, so the lock prompt and the paper's words never touch the app's main process; the app starts it with
// KeykinClient.approve(...) and reads the outcome from the slot's state ("last_action"). It refreshes the account
// first, so it acts on today's members (a device that joined since this phone last looked is included), and warns
// before a step that leaves this phone the account's only device. The app draws nothing here and is told no secret.
package keykin.android

import android.os.Bundle
import android.text.InputType
import android.view.WindowInsets
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import keykin.Device
import keykin.KeykinException
import org.json.JSONArray
import org.json.JSONObject

class KeykinApprove : FragmentActivity() {
    companion object {
        const val SLOT = "keykin.slot"; const val ACTION = "keykin.action"; const val KEY = "keykin.key"; const val ID = "keykin.id"; const val WITH = "keykin.with"
        /** The actions: report a device lost, check the paper, add the invited device, approve a pair request, remove a device with a pair. */
        val ACTIONS = setOf("report_lost", "paper_check", "add_invited", "pair_approve", "pair_remove")
    }
    private lateinit var line: TextView
    private lateinit var col: LinearLayout
    private var slot = ""; private var action = ""

    override fun onCreate(saved: Bundle?) {
        super.onCreate(saved)
        Proc.signerOnly("KeykinApprove")
        Memberships.init(this)
        slot = intent.getStringExtra(SLOT) ?: return finish()
        action = intent.getStringExtra(ACTION)?.takeIf { it in ACTIONS } ?: return finish()
        col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 40, 40, 40) }
        line = TextView(this).apply { textSize = 16f; text = "Checking your account…" }
        col.addView(line)
        setContentView(ScrollView(this).apply { addView(col)
            setOnApplyWindowInsetsListener { v, i -> val b = i.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime() or WindowInsets.Type.displayCutout()); v.setPadding(b.left, b.top, b.right, b.bottom); i } })
        val s = try { Memberships.signer(slot) } catch (_: Exception) { return done(false, "no_membership") }
        val d = s.device ?: return done(false, "no_membership")
        // Today's members first: a screen that acts on a stale list deals the wrong redeal (dry-run result 6).
        Thread { try { d.fetch() } catch (_: Exception) {}; runOnUiThread { show(s, d) } }.start()
    }

    private fun show(s: KeykinSigner, d: Device) {
        val others = d.memberKeys().filter { it != d.pub }
        val key = intent.getStringExtra(KEY).orEmpty()
        when (action) {
            "report_lost" -> {
                if (key !in others) return done(false, "not_a_device", key)
                val last = others.size == 1
                line.text = "Report ${key.take(12)}… lost? It is removed from your account and can't sign any more. Only do this for a device you no longer have." +
                    (if (last) "\n\nThis is your last other device: after this, this phone is the account's only device. Without the paper you won't be able to get back in if you lose it." else "")
                approveWith(s, d, "Report lost", PaperEntry.removeList(slot, key)) { list, ap -> d.submit(list, ap); "reported lost" }
            }
            "paper_check" -> {
                line.text = "Type the 24 words of your paper to check they are this account's. The words stay on this phone."
                val words = wordsField()
                button("Check the paper") { val w = words(); Thread {
                    val ok = try { PaperEntry.check(slot, w) } catch (e: Exception) { return@Thread done(false, (e as? KeykinException)?.code ?: "failed") }
                    done(true, if (ok) "this account's paper" else "not this account's paper") }.start() }
            }
            "add_invited" -> {
                val list = try { d.inviteAddList() } catch (e: KeykinException) { return done(false, e.code) }
                line.text = "Add the new device to your account? Only if you just typed the number it shows."
                if (list == null) { Thread { finishWith { d.addInvited(null); "added" } }.start(); return }
                approveWith(s, d, "Add device", list) { l, ap -> d.addInvited(ap); "added" }
            }
            "pair_approve" -> {
                val id = intent.getStringExtra(ID).orEmpty()
                val ask = d.pairAsks[id] ?: return done(false, "unknown_pair")
                line.text = "${ask.getString("from").take(12)}… asks this phone to approve: ${describe(ask.getJSONArray("list"))}\n\nType the 6 digits the other device shows. Only if you are holding both."
                val code = EditText(this).apply { hint = "6 digits"; inputType = InputType.TYPE_CLASS_NUMBER }; col.addView(code)
                button("Approve") { val c = code.text.toString().trim(); Thread {
                    val ok = try { d.pairApprove(id, c) } catch (e: Exception) { return@Thread done(false, (e as? KeykinException)?.code ?: "failed") }
                    done(ok, if (ok) "approved" else "the digits don't match") }.start() }
            }
            "pair_remove" -> {
                val with = intent.getStringExtra(WITH).orEmpty()
                if (key !in others || with !in others || with == key) return done(false, "not_a_device", key)
                val list = PaperEntry.removeList(slot, key)
                val (code, approval) = try { d.pairStart(list, with) } catch (e: KeykinException) { return done(false, e.code) }
                line.text = "To remove ${key.take(12)}…, type this code on ${with.take(12)}…:\n\n$code\n\nWaiting for it (up to 10 minutes)."
                Thread {
                    val r = try { val a = approval.get(10, java.util.concurrent.TimeUnit.MINUTES) ?: throw KeykinException("refused"); d.submit(list, a); null }
                        catch (e: KeykinException) { e.code } catch (_: Exception) { "expired" }
                    done(r == null, r ?: "removed", key)
                }.start()
            }
        }
        button("Cancel") { done(false, "cancelled") }
    }

    /** Approve `list` with this phone's lock (the prompt), or with the paper's words on a lockless phone; then `run`. */
    private fun approveWith(s: KeykinSigner, d: Device, label: String, list: JSONArray, run: (JSONArray, JSONObject) -> String) {
        val lock = s.lock()
        val words = if (lock == null) { col.addView(TextView(this).apply { text = "This phone has no lock: approve with the paper's 24 words." }); wordsField() } else null
        button(label) {
            if (lock != null) LockPrompt.approveList(this, d, lock, list, label, line.text.toString().lineSequence().first()) { a, why ->
                if (a == null) return@approveList done(false, why ?: "not approved")
                Thread { finishWith { run(list, a) } }.start()
            } else {
                val w = words!!()
                if (w.size != 24) { line.text = "Type all 24 words of the paper first."; return@button }
                Thread { finishWith { val sk = keykin.Backup.readBackupWords(w); try { run(list, d.approveWithPaper(list, sk)) } finally { sk.fill(0) } } }.start()
            }
        }
    }
    private fun finishWith(f: () -> String) = try { done(true, f(), intent.getStringExtra(KEY)) } catch (e: KeykinException) { done(false, e.code) } catch (_: Exception) { done(false, "failed") }
    private fun wordsField(): () -> List<String> {
        val f = EditText(this).apply { hint = "the paper's 24 words"; minLines = 2
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS }
        col.addView(f)
        return { f.text.toString().trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.also { runOnUiThread { f.setText("") } } }
    }
    private fun button(label: String, f: () -> Unit) { col.addView(Button(this).apply { text = label; filterTouchesWhenObscured = true; setOnClickListener { f() } }) }
    private fun describe(list: JSONArray) = (0 until list.length()).joinToString("; ") { k -> list.getJSONObject(k).let { c ->
        when { c.has("remove") -> "remove ${c.getString("remove").take(12)}…"; c.has("add") -> "add a device"; c.has("redeal") -> "new key pieces"; else -> c.keys().next() } } }
    /** The outcome goes to the slot's state; the screen closes. */
    private fun done(ok: Boolean, detail: String, key: String? = null) {
        Outcomes.put(slot, action, ok, detail, key)
        runOnUiThread { finish() }
    }
}
