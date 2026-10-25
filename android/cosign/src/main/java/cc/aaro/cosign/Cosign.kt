package cc.aaro.cosign

import android.app.Application
import android.content.Context

/**
 * The Cosign library, as an app sets it up: [init] once from its Application, which runs in
 * both of its processes (Proc). The signer process (":signer") gets the keys, [signers]; the
 * app's own process gets [accounts], which reaches them only through SignerService.
 *
 * The library draws nothing. What it needs on screen it asks of the app ([Host]), and what
 * needs the person's answer reaches the app through [Signer.Listener] and [Nip55Request].
 */
object Cosign {
    /** What the library asks of the app. */
    interface Host {
        /**
         * The paper backup's code, or a key taken out, is ready ([Ui.paper], [Ui.takeOut]):
         * show it from an activity of the app's that runs in the signer process and reads the
         * account's [Signer.ui]. It never reaches the app's own process.
         */
        fun reveal(context: Context, slot: String)
    }

    lateinit var context: Context
        private set
    lateinit var host: Host
        private set
    /** The accounts as the UI sees them, through the signer process. App's process only. */
    lateinit var accounts: Accounts
        private set
    /** The keys themselves. Signer process only. */
    lateinit var signers: Signers
        private set

    fun init(app: Application, host: Host) {
        context = app
        this.host = host
        if (Proc.isSigner) {
            signers = Signers(app)
            Startup.mark("signers")
        } else {
            accounts = Accounts(app).also { it.bind() }
            Startup.mark("accounts")
        }
    }
}

/** The app's name as it calls itself (its label), for what the library says. */
val appName: String get() = Cosign.context.applicationInfo.loadLabel(Cosign.context.packageManager).toString()
