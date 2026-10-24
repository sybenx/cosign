package cc.aaro.cosign

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Approve / Deny on a request, a batch of deletions, or Undo on a deletion, tapped in its notification. */
class DecisionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val phone = CosignApp.instance.phone
        val approve = intent.getBooleanExtra("approve", false)
        intent.getStringExtra("cancel")?.let { return phone.cancelDeletion(it) }
        intent.getStringExtra("batch")?.let { return phone.decideBatch(it, approve) }
        val id = intent.getStringExtra("id") ?: return
        phone.decide(id, approve)
    }
}
