package cc.aaro.cosign

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Approve / Deny tapped on a request's notification. */
class DecisionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val id = intent.getStringExtra("id") ?: return
        CosignApp.instance.phone.decide(id, intent.getBooleanExtra("approve", false))
    }
}
