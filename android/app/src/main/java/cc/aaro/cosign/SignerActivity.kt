package cc.aaro.cosign

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import cc.aaro.cosign.ui.CosignTheme
import cc.aaro.cosign.ui.PaperSheet
import cc.aaro.cosign.ui.TakeOutSheet

/**
 * What only the signer process may put on screen: the paper backup's code, shown once,
 * and a key taken out. It opens over the app when the UI says one is ready (the UI only
 * knows that it is, never what it says) and closes when it's been dealt with.
 */
class SignerActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Proc.signerOnly("SignerActivity")
        enableEdgeToEdge(SystemBarStyle.dark(android.graphics.Color.TRANSPARENT), SystemBarStyle.dark(android.graphics.Color.TRANSPARENT))
        val s = intent.getStringExtra("slot")?.let { CosignApp.instance.signers.signer(it) } ?: return finish()
        setContent {
            CosignTheme {
                val ui by s.ui.collectAsState()
                val paper = ui.paper
                val takeOut = ui.takeOut?.takeIf { it.stage == TakeOut.Stage.SHOWING }
                when {
                    // Shown once: back doesn't throw it away; "I've kept it safe" does.
                    paper != null -> { BackHandler {}; PaperSheet(paper, s::closePaper) }
                    takeOut != null -> TakeOutSheet(takeOut, s::closeTakeOut)
                    else -> LaunchedEffect(Unit) { finish() }
                }
            }
        }
    }

    companion object {
        fun open(context: Context, slot: String) = context.startActivity(
            Intent(context, SignerActivity::class.java).putExtra("slot", slot).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        )
    }
}
