package cc.aaro.cosign.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cc.aaro.cosign.Ask
import cc.aaro.cosign.Change
import cc.aaro.cosign.BatchAsk
import cc.aaro.cosign.Connect
import cc.aaro.cosign.CosignApp
import cc.aaro.cosign.MoveIn
import cc.aaro.cosign.Deleted
import cc.aaro.cosign.Deleting
import cc.aaro.cosign.SiteSummary
import cc.aaro.cosign.Future
import cc.aaro.cosign.Line
import cc.aaro.cosign.Offer
import cc.aaro.cosign.Phone
import cc.aaro.cosign.Site
import cc.aaro.cosign.Ui
import cc.aaro.cosign.appName
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

@Composable
fun App(phone: Phone, ui: Ui) {
    var scanning by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxSize().background(Vault.Ground)) {
        when {
            scanning -> {
                BackHandler { scanning = false }
                val context = androidx.compose.ui.platform.LocalContext.current
                Box(Modifier.fillMaxSize()) {
                    QrScanner(Modifier.fillMaxSize()) { scanning = false; phone.scanned(it) }
                    // A code copied instead of shown (nostrconnect://, cosign:, a sign-in link): the same as scanning it.
                    Row(Modifier.align(Alignment.BottomCenter).safeDrawingPadding().padding(24.dp)) {
                        TextButton({
                            val t = pasted(context).trim()
                            if (t.isEmpty()) phone.showError("Copy the site's code first, then tap Paste a code.") else { scanning = false; phone.scanned(t) }
                        }) { Text("Paste a code", color = Vault.Teal) }
                        Spacer(Modifier.width(16.dp))
                        TextButton({ scanning = false }) { Text("Cancel", color = Vault.Text) }
                    }
                }
            }
            ui.offer != null -> JoinPrompt(ui.offer, phone::accept, phone::decline)
            ui.joining != null -> Joining(ui.joining, phone::decline)
            ui.joinCode != null && ui.member == null -> JoinCode(ui.joinCode, ui.error, phone::cancelJoin)
            ui.restoring != null && ui.member == null -> RestoringScreen(ui.restoring, phone::cancelRestore)
            ui.member == null -> Column(Modifier.fillMaxSize()) {
                var importing by remember { mutableStateOf(false) }
                Box(Modifier.weight(1f)) { Welcome(ui.error, onCreate = phone::createAccount, onJoin = phone::startJoin, onScan = { phone.clearError(); scanning = true }, onPaste = phone::pastedBackup, onHave = { phone.clearError(); importing = true }) }
                if (importing) ImportSheet({ importing = false }) { chars -> importing = false; phone.secretFrom(chars)?.let(phone::importKey) ?: phone.showError("That isn't an nsec (or a 64-character hex key). Nothing was kept.") }
                // A place for another key: the ones you have are a tap away.
                val others = CosignApp.instance.accounts.all.filter { it !== phone && it.isMember }
                if (others.isNotEmpty()) TextButton({ CosignApp.instance.accounts.forget(phone.slot); CosignApp.instance.accounts.show(others.first().slot) },
                    Modifier.align(Alignment.CenterHorizontally).safeDrawingPadding().padding(bottom = 12.dp)) { Text("Back to ${accountName(others.first())}", color = Vault.Muted) }
            }
            else -> Discover(phone, ui) { phone.clearError(); scanning = true }
        }
        // With several keys, every question says which one it's about.
        val which = if (CosignApp.instance.accounts.all.count { it.isMember } > 1) phone.label else null
        ui.connect?.let { ConnectSheet(it, which, phone::confirmConnect, phone::closeConnect) }
        ui.moveIn?.let { MoveInSheet(it, phone::acceptMove, phone::closeMove) }
        ui.summary?.let { UndoSiteSheet(it, phone::confirmUndoSite, phone::closeSummary) }
        ui.adding?.let { AddDeviceSheet(it, phone) }
        ui.reporting?.let { ReportLostSheet(it, phone) }
        ui.removedBy?.let { RemovedSheet(it, phone) }
        ui.paper?.let { PaperSheet(it, phone::closePaper) }
        if (ui.askPaper && ui.paper == null && ui.paperStatus == null) PaperPrompt(phone)
        ui.serverChoice?.let { ServerChoiceSheet(it, ui.paperStatus, phone) }
        ui.takeOut?.let { TakeOutSheet(it, phone) }
        GuardNotices(ui, phone)
    }
}

// --- Taking your account out of Cosign ----------------------------------------------------

/** Under Advanced: take it out (with the paper at once, or through a server after the wait), then optionally remove the servers' pieces. */
@Composable
private fun TakeOutEntry(phone: Phone, onScan: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var open by remember { mutableStateOf(false) }
    var then by remember { mutableStateOf<(() -> Unit)?>(null) }
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) then?.invoke()
    }
    val locked = { title: String, action: () -> Unit ->
        val ask = lockIntent(context, title, "Confirm it's you")
        if (ask == null) phone.showError("Set a screen lock on this phone first.") else { then = action; lock.launch(ask) }
    }
    Column(Modifier.padding(top = 10.dp)) {
        TextButton({ open = !open }, contentPadding = PaddingValues(0.dp)) { Text("Take my account out of Cosign", color = Vault.Teal) }
        if (open) {
            Muted("This puts your secret key (nsec) back together on this phone and shows it, so you can use it elsewhere. Every one of your devices is told.")
            Spacer(Modifier.height(8.dp))
            TextButton({ locked("Take my account out") { phone.askTakeOutPaper(true); onScan() } }, contentPadding = PaddingValues(0.dp)) {
                Text("Now, with my paper backup", color = Vault.Teal)
            }
            TextButton({ locked("Take my account out") { phone.takeOutViaServers() } }, contentPadding = PaddingValues(0.dp)) {
                Text("Without it: after a 3-day wait your other devices can stop", color = Vault.Teal)
            }
            Spacer(Modifier.height(6.dp))
            Muted("Afterwards you can also remove your servers' pieces: they stop at once, and delete them after 3 days unless one of your devices stops it.")
            TextButton({ locked("Remove my servers' pieces") { phone.forgetServers() } }, contentPadding = PaddingValues(0.dp)) {
                Text("Remove my servers' pieces", color = Vault.Danger)
            }
        }
    }
}

/** Waiting, the key itself (once, no screenshots), or why not. */
@Composable
private fun TakeOutSheet(t: cc.aaro.cosign.TakeOut, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? android.app.Activity
    if (t.stage == cc.aaro.cosign.TakeOut.Stage.SHOWING) androidx.compose.runtime.DisposableEffect(Unit) {
        activity?.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { activity?.window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE) }
    }
    BackHandler { phone.closeTakeOut() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            when (t.stage) {
                cc.aaro.cosign.TakeOut.Stage.WAITING -> {
                    Text("Taking your account out", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    Spacer(Modifier.height(10.dp))
                    Text(t.text, style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
                    t.until?.takeIf { it > 0 }?.let {
                        Spacer(Modifier.height(6.dp))
                        Text("Ready after ${java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(it * 1000))}. Keep Cosign installed.",
                            style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
                    }
                }
                cc.aaro.cosign.TakeOut.Stage.SHOWING -> {
                    Text("Your secret key", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    Spacer(Modifier.height(10.dp))
                    Text(t.nsec ?: "", fontFamily = PlexMono, color = Vault.Text, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Text("Account: ${short(t.npub ?: "")}", color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
                    if (t.twinUnknown) {
                        Spacer(Modifier.height(6.dp))
                        Muted("This may not look like the nsec you started with. It's the same account (compare the npub) and works everywhere.")
                    }
                    Spacer(Modifier.height(14.dp))
                    var copied by remember { mutableStateOf(false) }
                    OutlinedButton({ copySecret(context, "Nostr key", t.nsec ?: ""); copied = true; clearClipLater(context) }, Modifier.fillMaxWidth().height(48.dp), border = BorderStroke(1.dp, Vault.Line)) {
                        Text(if (copied) "Copied (cleared in a minute)" else "Copy", color = Vault.Text)
                    }
                    Muted("Anyone with this key is you. Keep it in a password manager.")
                }
                cc.aaro.cosign.TakeOut.Stage.FAILED -> {
                    Text("Not taken out", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    Spacer(Modifier.height(10.dp))
                    Text(t.text, style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
                }
            }
            Spacer(Modifier.height(16.dp))
            Button(phone::closeTakeOut, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
                Text(if (t.stage == cc.aaro.cosign.TakeOut.Stage.WAITING) "Close (it keeps going)" else "Done")
            }
        }
    }
}

/** Clear the clipboard a minute after a key was copied, if it still holds it. */
private fun clearClipLater(context: android.content.Context) {
    val cb = context.getSystemService(android.content.ClipboardManager::class.java) ?: return
    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ try { cb.clearPrimaryClip() } catch (_: Exception) {} }, 60_000)
}

/** Another of your devices is taking the account out, or removing the servers' pieces: say so, with Stop (after this device's lock). */
@Composable
private fun GuardNotices(ui: cc.aaro.cosign.Ui, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var hidden by remember { mutableStateOf(setOf<String>()) }
    val g = ui.guards.firstOrNull { it.id !in hidden && it.kind != "remove" && (it.state == "waiting" || (it.state == "done" && it.paper)) && ui.takeOut == null } ?: return
    var stopping by remember { mutableStateOf<String?>(null) }
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) stopping?.let { id -> phone.cancelGuard(id); hidden = hidden + id }
    }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            val title = when {
                g.kind == "take_out" && g.state == "done" -> "Your account was taken out of Cosign"
                g.kind == "take_out" -> "Your account is being taken out of Cosign"
                else -> "Your servers' pieces are being removed"
            }
            Text(title, style = MaterialTheme.typography.titleLarge, color = Vault.Amber)
            Spacer(Modifier.height(10.dp))
            val whenText = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(g.until * 1000))
            Text(if (g.state == "done") "On ${g.by}, with your paper backup. If that wasn't you, someone has that device and your paper: report it lost."
                else "From ${g.by}. It happens after $whenText unless you stop it. If that wasn't you, stop it now.",
                style = MaterialTheme.typography.bodyMedium, color = Vault.Text)
            Spacer(Modifier.height(20.dp))
            if (g.state == "waiting") Button({
                val ask = lockIntent(context, "Stop it", "Confirm it's you")
                if (ask == null) phone.showError("Set a screen lock on this phone first.") else { stopping = g.id; lock.launch(ask) }
            }, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Amber, Vault.Ground)) { Text("Stop it") }
            OutlinedButton({ hidden = hidden + g.id }, Modifier.fillMaxWidth().height(52.dp).padding(top = 8.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("It's me", color = Vault.Text) }
        }
    }
}

@Composable
private fun Page(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 24.dp, vertical = 16.dp), content = content)

@Composable
private fun Welcome(error: String?, onCreate: () -> Unit, onJoin: () -> Unit, onScan: () -> Unit, onPaste: (String) -> Unit, onHave: () -> Unit) = Page {
    val context = androidx.compose.ui.platform.LocalContext.current
    Spacer(Modifier.weight(1f))
    Text(appName, style = MaterialTheme.typography.headlineMedium, color = Vault.Text)
    Spacer(Modifier.height(12.dp))
    Text(
        "Search and discover what people are posting. With an account you can like and follow, and sign in to sites; " +
            "anything destructive waits for you on this phone.",
        style = MaterialTheme.typography.bodyLarge, color = Vault.Muted,
    )
    error?.let { Spacer(Modifier.height(16.dp)); Text(it, color = Vault.Danger, style = MaterialTheme.typography.bodyMedium) }
    Spacer(Modifier.weight(1f))
    Button(onCreate, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
        Text("Create your account", style = MaterialTheme.typography.labelLarge)
    }
    Spacer(Modifier.height(8.dp))
    Text("Made with Cosign's servers; no one, this phone included, ever holds all of it.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted,
        modifier = Modifier.align(Alignment.CenterHorizontally))
    Spacer(Modifier.height(8.dp))
    TextButton(onJoin, Modifier.align(Alignment.CenterHorizontally)) { Text("Sign in with another device", color = Vault.Teal) }
    TextButton(onHave, Modifier.align(Alignment.CenterHorizontally)) { Text("I already have an account", color = Vault.Teal) }
    TextButton(onScan, Modifier.align(Alignment.CenterHorizontally)) { Text("Restore from your backup", color = Vault.Muted) }
    TextButton({ onPaste(pasted(context)) }, Modifier.align(Alignment.CenterHorizontally)) { Text("Paste your backup code instead", color = Vault.Muted) }
    TextButton(onScan, Modifier.align(Alignment.CenterHorizontally)) { Text("Set up with a server's code", color = Vault.Muted) }
}

/**
 * "I already have an account": paste its nsec. The field is a plain Android one, so what's
 * in it is read as characters (never a String) and wiped; no screenshots while it's open;
 * the clipboard is cleared once it's used.
 */
@Composable
private fun ImportSheet(onClose: () -> Unit, onKey: (CharArray) -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? android.app.Activity
    androidx.compose.runtime.DisposableEffect(Unit) {
        activity?.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { activity?.window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE) }
    }
    var field by remember { mutableStateOf<android.widget.EditText?>(null) }
    val take = {
        field?.let { f ->
            val e = f.text
            val chars = CharArray(e.length).also { e.getChars(0, e.length, it, 0) }
            e.clear()
            context.getSystemService(android.content.ClipboardManager::class.java)?.let { cb -> try { cb.clearPrimaryClip() } catch (_: Exception) {} }
            onKey(chars)
        }
    }
    BackHandler(onBack = onClose)
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            Text("Bring your account", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            Text("Paste its secret key (nsec). This phone splits it with your servers, so no one place holds it, then forgets it. You'll make a backup next.",
                style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
            Spacer(Modifier.height(16.dp))
            androidx.compose.ui.viewinterop.AndroidView({ ctx ->
                android.widget.EditText(ctx).apply {
                    inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                    importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                    hint = "nsec1…"
                    setTextColor(android.graphics.Color.WHITE); setHintTextColor(android.graphics.Color.GRAY)
                    isSingleLine = true
                    field = this
                }
            }, Modifier.fillMaxWidth())
            Spacer(Modifier.height(20.dp))
            Button({ take() }, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Bring it into Cosign") }
            TextButton(onClose, Modifier.align(Alignment.CenterHorizontally)) { Text("Cancel", color = Vault.Muted) }
        }
    }
}

@Composable
private fun Joining(text: String, onCancel: () -> Unit) = Page {
    Spacer(Modifier.weight(1f))
    CircularProgressIndicator(color = Vault.Teal, modifier = Modifier.align(Alignment.CenterHorizontally))
    Spacer(Modifier.height(20.dp))
    Text(text, color = Vault.Text, modifier = Modifier.align(Alignment.CenterHorizontally))
    Spacer(Modifier.weight(1f))
    TextButton(onCancel, Modifier.align(Alignment.CenterHorizontally)) { Text("Cancel", color = Vault.Muted) }
}

@Composable
private fun JoinPrompt(offer: Offer, onJoin: () -> Unit, onCancel: () -> Unit) = if (offer.plan != null) MakeKeyPrompt(onJoin, onCancel) else Page {
    Spacer(Modifier.height(24.dp))
    Text("Use your account on this phone?", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
    Spacer(Modifier.height(8.dp))
    Text(short(offer.group.npub), fontFamily = PlexMono, color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
    Spacer(Modifier.height(20.dp))
    Text("This phone gets its own part of your account. Nothing can post as you from just one place, this phone included.",
        color = Vault.Text, style = MaterialTheme.typography.bodyLarge)
    Spacer(Modifier.height(12.dp))
    Text("Almost everything happens without asking. Anything destructive — unfollowing most people, wiping your profile, deleting a pile of posts — waits for you here.",
        color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.weight(1f))
    Button(onJoin, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Use it on this phone", style = MaterialTheme.typography.labelLarge) }
    Spacer(Modifier.height(8.dp))
    TextButton(onCancel, Modifier.fillMaxWidth()) { Text("Not now", color = Vault.Muted) }
}

/** A weighted key isn't made yet: this phone and your servers make it together. */
@Composable
private fun MakeKeyPrompt(onJoin: () -> Unit, onCancel: () -> Unit) = Page {
    Spacer(Modifier.height(24.dp))
    Text("Create your account?", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
    Spacer(Modifier.height(20.dp))
    Text(
        "This phone and the page you scanned set it up together. Nobody holds all of it, not even this phone, so a lost phone or a hacked site can't post as you.",
        color = Vault.Text, style = MaterialTheme.typography.bodyLarge,
    )
    Spacer(Modifier.height(12.dp))
    Text("Almost everything happens without asking. Anything destructive — unfollowing most people, wiping your profile, deleting a pile of posts — waits for you here.",
        color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.weight(1f))
    Button(onJoin, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Create my account", style = MaterialTheme.typography.labelLarge) }
    Spacer(Modifier.height(8.dp))
    TextButton(onCancel, Modifier.fillMaxWidth()) { Text("Not now", color = Vault.Muted) }
}

/** A key moving in from a web page: the five digits to type there, then whether to keep it. */
@Composable
private fun MoveInSheet(m: MoveIn, onKeep: () -> Unit, onClose: () -> Unit) {
    BackHandler { onClose() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            val digits: @Composable (String) -> Unit = { code ->
                Text(code.chunked(1).joinToString(" "), fontFamily = PlexMono, style = MaterialTheme.typography.displaySmall, color = Vault.Teal,
                    modifier = Modifier.align(Alignment.CenterHorizontally))
            }
            when (m.stage) {
                MoveIn.Stage.WAITING -> Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(22.dp), color = Vault.Teal, strokeWidth = 2.dp)
                    Spacer(Modifier.width(14.dp))
                    Text(m.text ?: "Working…", color = Vault.Text)
                }
                MoveIn.Stage.CODE -> {
                    Text("Type this on the page", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    Spacer(Modifier.height(16.dp))
                    digits(m.code ?: "")
                    Spacer(Modifier.height(16.dp))
                    Text("It proves the page is talking to this phone. Your key moves only once you've typed it.", color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(18.dp))
                    OutlinedButton(onClose, Modifier.fillMaxWidth().height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Cancel", color = Vault.Text) }
                }
                MoveIn.Stage.ACCEPT -> {
                    Text("Keep this key?", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    Spacer(Modifier.height(10.dp))
                    Text(m.text ?: "", color = Vault.Text, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("From now on it signs through your servers, with this phone. The page no longer needs to hold it.", color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(20.dp))
                    OutlinedButton(onClose, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Discard", color = Vault.Text) }
                    Spacer(Modifier.height(10.dp))
                    Button(onKeep, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Keep it") }
                }
                MoveIn.Stage.DONE, MoveIn.Stage.FAILED -> {
                    Text(if (m.stage == MoveIn.Stage.DONE) "All set" else "Not done", style = MaterialTheme.typography.titleLarge,
                        color = if (m.stage == MoveIn.Stage.DONE) Vault.Teal else Vault.Danger)
                    Spacer(Modifier.height(8.dp))
                    Text(m.text ?: "", color = Vault.Text, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(18.dp))
                    Button(onClose, Modifier.fillMaxWidth().height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Edge, Vault.Text)) { Text("OK") }
                }
            }
        }
    }
}

/** Connecting a site: the one-tap consent of QRST at its lowest check, then progress. */
@Composable
private fun ConnectSheet(c: Connect, which: String?, onConnect: () -> Unit, onClose: () -> Unit) {
    BackHandler { onClose() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            when (c.stage) {
                Connect.Stage.CONFIRM -> {
                    Text("Use your account on ${c.origin}?", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    which?.let { Text("as $it", fontFamily = PlexMono, color = Vault.Teal, style = MaterialTheme.typography.bodyMedium) }
                    Spacer(Modifier.height(10.dp))
                    Text("It can post, like and follow as you. Anything destructive, like unfollowing everyone or deleting posts, comes to this phone first.",
                        style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
                    Spacer(Modifier.height(6.dp))
                    Text("Remove it under Your account any time. That stops it from then on; it doesn't undo what it already did.",
                        style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
                    Spacer(Modifier.height(20.dp))
                    // Declining is never the weaker control; the affirmative one names the site.
                    OutlinedButton(onClose, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Don't connect", color = Vault.Text) }
                    Spacer(Modifier.height(10.dp))
                    Button(onConnect, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
                        Text("Use it on ${c.origin}", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
                Connect.Stage.WORKING -> Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(22.dp), color = Vault.Teal, strokeWidth = 2.dp)
                        Spacer(Modifier.width(14.dp))
                        Text(c.message ?: "Connecting…", color = Vault.Text)
                    }
                    Spacer(Modifier.height(18.dp))
                    OutlinedButton(onClose, Modifier.fillMaxWidth().height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Cancel", color = Vault.Text) }
                }
                Connect.Stage.DONE, Connect.Stage.FAILED -> {
                    Text(if (c.stage == Connect.Stage.DONE) "Connected" else "Not connected", style = MaterialTheme.typography.titleLarge,
                        color = if (c.stage == Connect.Stage.DONE) Vault.Teal else Vault.Danger)
                    Spacer(Modifier.height(8.dp))
                    Text(c.message ?: "", color = Vault.Text, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(18.dp))
                    Button(onClose, Modifier.fillMaxWidth().height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Edge, Vault.Text)) { Text("OK") }
                }
            }
        }
    }
}

/**
 * Your account, behind your picture on the home screen: your profile, devices, connected
 * apps and sites, keeping it safe, and what changed. How it works (servers, relays) is under Advanced.
 */
@Composable
internal fun AccountScreen(phone: Phone, ui: Ui, onScan: () -> Unit, onProfile: () -> Unit, onBack: () -> Unit) {
    val m = ui.member!!
    var leaving by remember { mutableStateOf(false) }
    var advanced by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() } }
    val people by cc.aaro.cosign.People.known.collectAsState()
    val me = people[m.group.groupX]

    LazyColumn(Modifier.fillMaxSize().safeDrawingPadding(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onBack, Modifier.padding(end = 8.dp).size(32.dp)) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Vault.Text)
                }
                Text("Your account", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            }
            Spacer(Modifier.height(16.dp))
            var switching by remember { mutableStateOf(false) }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Row(Modifier.weight(1f).clickable(onClick = onProfile), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(me, m.group.groupX, 52)
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(me?.name ?: "Your profile", style = MaterialTheme.typography.titleMedium, color = Vault.Text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        if (me?.name == null) Text("No name or picture yet", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
                        Text(short(m.group.npub), fontFamily = PlexMono, style = MaterialTheme.typography.labelSmall, color = Vault.Muted)
                    }
                }
                TextButton({ switching = true }) { Text("Switch ▾", color = Vault.Teal) }
            }
            if (switching) KeysSheet(phone) { switching = false }
            // Another account of yours with something waiting: say so here too, not only in notifications.
            val waiting = CosignApp.instance.accounts.all.filter { it !== phone }.map { it to it.ui.collectAsState().value }
                .filter { (_, u) -> u.asks.isNotEmpty() || u.batchAsks.isNotEmpty() }
            for ((p, u) in waiting) TextButton({ CosignApp.instance.accounts.show(p.slot) }, contentPadding = PaddingValues(0.dp)) {
                Text("${accountName(p)}: ${u.asks.size + u.batchAsks.size} waiting for you. Switch", color = Vault.AmberText, style = MaterialTheme.typography.bodySmall)
            }
            ui.error?.let { Text(it, color = Vault.Danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp)) }
        }
        // The paper backup's nudge is on the home screen; here it's under Keep your account safe.
        ui.recovery?.let { (name, until) -> if (!RecoveryOk.has(until)) item { RecoveryCard(name, until, phone) } }
        items(ui.future, key = { "future:" + it.id }) { f -> FutureCard(f) { phone.removeFuture(f) } }
        items(ui.deleting, key = { "deleting:" + it.batch }) { d -> DeletingCard(d, now) { phone.cancelDeletion(d.batch) } }
        items(ui.batchAsks, key = { "batch:" + it.batch }) { b -> BatchCard(b, now) { approve -> phone.decideBatch(b.batch, approve) } }
        items(ui.asks, key = { "ask:" + it.id }) { ask -> AskCard(ask, now) { approve -> phone.decide(ask.id, approve) } }

        item { Heading("Your devices") }
        items(m.group.members.filter { it.role != "server" && it.role != "backup" }, key = { "member:" + it.idx }) { d ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(8.dp).background(if (d.idx == m.idx || ui.online[d.idx] == true) Vault.Teal else Vault.Field, CircleShape))
                Spacer(Modifier.width(10.dp))
                Text(if (d.idx == m.idx) "${d.name} (this one)" else d.name, color = Vault.Text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                if (d.idx != m.idx) TextButton({ phone.askReportLost(d) }) { Text("Report lost", color = Vault.Danger, style = MaterialTheme.typography.bodySmall) }
            }
        }
        item { TextButton(onScan, contentPadding = PaddingValues(0.dp)) { Text("Add a device", color = Vault.Teal) } }

        item { Heading("Apps and sites you're signed in to") }
        item {
            Button(onScan, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
                Text("Sign in to a site", style = MaterialTheme.typography.labelLarge)
            }
        }
        if (ui.sites.isEmpty()) item { Muted("None yet. To use your account on a website, tap Sign in to a site and scan the code it shows.") }
        // One entry per website, with each way it's connected inside.
        items(ui.sites.groupBy { it.origin }.toList(), key = { "site:" + it.first }) { (origin, grants) ->
            SiteGroup(origin, grants, onRemove = phone::removeSite, onUndo = phone::askUndoSite)
        }

        // Accounts from before weighted keys (threshold 2) can't have a paper: it could sign alone.
        if (m.group.threshold >= 4) {
            item { Heading("Keep your account safe") }
            item { PaperRow(m.group.members.any { it.role == "backup" }, ui.paperStatus, phone) }
        }

        item { Heading("Recent changes") }
        if (ui.changes.isEmpty()) item { Muted("Follows, profile, bookmarks… every change shows up here, with Undo.") }
        items(ui.changes.take(12), key = { "change:" + it.id }) { ChangeRow(it) { phone.undo(it) } }

        if (ui.deleted.isNotEmpty()) {
            item { Heading("Deleted, with copies kept") }
            items(ui.deleted, key = { "deleted:" + it.id }) { DeletedRow(it) { phone.repost(it) } }
        }

        item {
            Row(Modifier.fillMaxWidth().padding(top = 10.dp).clickable { advanced = !advanced }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Advanced", style = MaterialTheme.typography.titleSmall, color = Vault.Muted, modifier = Modifier.weight(1f))
                Text(if (advanced) "▴" else "▾", color = Vault.Muted)
            }
        }
        if (advanced) {
            item {
                Muted("Your account is a Nostr key, split between this phone and your servers. Any of your servers with this phone can sign; your servers alone can't.")
                Spacer(Modifier.height(10.dp))
                val context = androidx.compose.ui.platform.LocalContext.current
                Text(short(m.group.npub), fontFamily = PlexMono, color = Vault.Text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.clickable {
                    context.getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(android.content.ClipData.newPlainText("npub", m.group.npub))
                })
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (mem in m.group.members) Chip(if (mem.idx == m.idx) "This phone" else mem.name, ui.online[mem.idx] == true, Modifier.weight(1f))
                }
                if (ui.relaysUp == 0) Text("No relay connection. Retrying…", color = Vault.Danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
            }
            if (m.group.threshold >= 4) item { TextButton({ phone.chooseServer() }, contentPadding = PaddingValues(0.dp)) { Text("Add a server", color = Vault.Teal) } }
            item { TranslateSetting() }
            item { TakeOutEntry(phone, onScan) }
            item { Heading("On this phone") }
            items(ui.log.take(20)) { LogLine(it) }
            item {
                Spacer(Modifier.height(12.dp))
                Muted("${ui.relaysUp}/${m.group.relays.size} relays · " + if (ui.push != null) "ntfy wakes this phone for approvals" else "no ntfy: approvals arrive while $appName is running")
                TextButton({ leaving = true }, contentPadding = PaddingValues(0.dp)) { Text("Remove this phone from your account", color = Vault.Danger, style = MaterialTheme.typography.bodySmall) }
            }
        }
    }

    if (leaving) AlertDialog(
        onDismissRequest = { leaving = false },
        title = { Text("Remove this phone?") },
        text = { Text("This deletes this phone's share of your key. Your servers keep signing everyday things, but nothing destructive can be approved until you set up a new key.") },
        confirmButton = { TextButton({ leaving = false; phone.leave() }) { Text("Delete the share", color = Vault.Danger) } },
        dismissButton = { TextButton({ leaving = false }) { Text("Keep it") } },
        containerColor = Vault.Surface,
    )
}

/** Your own LibreTranslate: notes in other languages are translated instead of left out. */
@Composable
private fun TranslateSetting() {
    val url by cc.aaro.cosign.Translate.url.collectAsState()
    val key by cc.aaro.cosign.Translate.key.collectAsState()
    var typedKey by remember(key) { mutableStateOf(key) }
    val status by cc.aaro.cosign.Translate.status.collectAsState()
    var typed by remember(url) { mutableStateOf(url) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    Column(Modifier.padding(top = 6.dp)) {
        Text("Use your own LibreTranslate server", style = MaterialTheme.typography.titleSmall, color = Vault.Text)
        Muted(if (url.isEmpty()) "Off: notes in other languages are left out of Discover. Set your LibreTranslate server to translate them instead."
            else "Notes in other languages are translated by your server. If it's down or slow, they're left out.")
        Spacer(Modifier.height(8.dp))
        androidx.compose.material3.OutlinedTextField(typed, { typed = it }, Modifier.fillMaxWidth(), singleLine = true,
            placeholder = { Text("https://translate.example.com", color = Vault.Muted) },
            textStyle = MaterialTheme.typography.bodyMedium.copy(color = Vault.Text))
        Spacer(Modifier.height(6.dp))
        androidx.compose.material3.OutlinedTextField(typedKey, { typedKey = it }, Modifier.fillMaxWidth(), singleLine = true,
            placeholder = { Text("API key (only if your server asks for one)", color = Vault.Muted) },
            visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
            textStyle = MaterialTheme.typography.bodyMedium.copy(color = Vault.Text))
        Row {
            TextButton({ cc.aaro.cosign.Translate.setKey(typedKey); cc.aaro.cosign.Translate.setUrl(typed); scope.launch { cc.aaro.cosign.Translate.check() } }, contentPadding = PaddingValues(0.dp)) {
                Text(if (typed.isBlank()) "Turn off" else "Save", color = Vault.Teal)
            }
        }
        status?.let { Muted(it) }
        Muted("Your LibreTranslate, over https.")
    }
}

/** An account, as you know it: its name, else its npub, shortened. */
internal fun accountName(p: Phone) = p.ui.value.member?.group?.groupX?.let { cc.aaro.cosign.People.known.value[it]?.name } ?: p.label

@Composable private fun Heading(text: String) = Text(text, style = MaterialTheme.typography.titleSmall, color = Vault.Muted, modifier = Modifier.padding(top = 10.dp))
@Composable private fun Muted(text: String) = Text(text, style = MaterialTheme.typography.bodySmall, color = Vault.Muted)

@Composable
internal fun FutureCard(f: Future, onRemove: () -> Unit) = Card(Vault.AmberEdge, Vault.AmberGround) {
    Text("Dated in the future", style = MaterialTheme.typography.labelMedium, color = Vault.AmberText)
    Spacer(Modifier.height(4.dp))
    Text(f.text, style = MaterialTheme.typography.bodyMedium, color = Vault.Text)
    Spacer(Modifier.height(14.dp))
    Button(onRemove, Modifier.fillMaxWidth().height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Amber, Vault.OnAmber)) { Text("Remove it", fontWeight = FontWeight.SemiBold) }
}

@Composable
internal fun AskCard(ask: Ask, now: Long, onDecide: (Boolean) -> Unit) = Card(Vault.AmberEdge, Vault.AmberGround) {
    val left = ((ask.expiresAt - now) / 1000).coerceAtLeast(0)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(question(ask.hold), style = MaterialTheme.typography.titleMedium, color = Vault.Text, modifier = Modifier.weight(1f))
        Text("${left}s", fontFamily = PlexMono, color = Vault.AmberText, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(6.dp))
    Text("${ask.app} asked. It doesn't happen unless you say yes.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    Spacer(Modifier.height(14.dp))
    YesNo(onDecide)
}

/** Yes or no to something that needs you. No is never the weaker button. */
@Composable
private fun YesNo(onDecide: (Boolean) -> Unit) = Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
    OutlinedButton({ onDecide(false) }, Modifier.weight(1f).height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Don't", color = Vault.Text) }
    Button({ onDecide(true) }, Modifier.weight(1f).height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Amber, Vault.OnAmber)) { Text("Yes", fontWeight = FontWeight.SemiBold) }
}

/**
 * What needs you, as a question about what would happen: "Remove 212 of your 230 follows"
 * becomes "Unfollow 212 people?". The words come from the policy (here and on your servers).
 */
internal fun question(what: String): String {
    val s = what.trim().removeSuffix(".").removeSuffix("?")
    fun people(n: String) = if (n == "1") "1 person" else "$n people"
    Regex("^Remove (\\d+) of your \\d+ follows?(?: \\(and add (\\d+)\\))?$").matchEntire(s)?.let {
        val add = it.groupValues[2]
        return "Unfollow ${people(it.groupValues[1])}" + (if (add.isEmpty()) "" else " and follow ${people(add)} instead") + "?"
    }
    Regex("^Empty your follow list \\(it has (\\d+) follows?\\)$").matchEntire(s)?.let { return "Unfollow all ${people(it.groupValues[1])}?" }
    Regex("^Empty your (.+) \\(it has (\\d+) (.+)\\)$").matchEntire(s)?.let { return "Remove all ${it.groupValues[2]} ${it.groupValues[3].replace("persons", "people")} from your ${it.groupValues[1]}?" }
    Regex("^(.+) dated in the future \\((.+)\\)$").matchEntire(s)?.let { return "Allow a ${it.groupValues[1].lowercase()} dated ${it.groupValues[2]}?" }
    Regex("^Delete (\\d+) (?:of your )?events?(?: for .*)?$").matchEntire(s)?.let { val n = it.groupValues[1]; return "Delete $n post${if (n == "1") "" else "s"}?" }
    Regex("^Delete (?:several|some) events?(?: for .*)?$").matchEntire(s)?.let { return "Delete several posts?" }
    Regex("^Wipe your profile: (.+)$").matchEntire(s)?.let { return "Clear your profile (${it.groupValues[1]})?" }
    if (s.startsWith("Ask relays to erase everything")) return "Erase everything you've ever posted?"
    return "$s?"
}

@Composable
private fun SiteGroup(origin: String, grants: List<Site>, onRemove: (Site) -> Unit, onUndo: (Site) -> Unit) = Column(
    Modifier.fillMaxWidth().background(Vault.Surface, RoundedCornerShape(12.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(12.dp)).padding(start = 14.dp, end = 6.dp, top = 8.dp, bottom = 8.dp),
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(origin.removePrefix("https://"), color = Vault.Text, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
        if (grants.size > 1) TextButton({ grants.forEach(onRemove) }) { Text("Remove all", color = Vault.AmberText) }
    }
    for (g in grants.sortedByDescending { it.lastUsed }) Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            "${g.via ?: if (g.parent == null) "Connected by code" else "Connected"} · used ${ago(g.lastUsed)}",
            color = Vault.Muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f),
        )
        TextButton({ onUndo(g) }) { Text("Undo all", color = Vault.Teal) }
        TextButton({ onRemove(g) }) { Text("Remove", color = Vault.AmberText) }
    }
}

@Composable
internal fun DeletingCard(d: Deleting, now: Long, onUndo: () -> Unit) = Card(Vault.Line, Vault.Surface) {
    val left = ((d.until - now) / 1000).coerceAtLeast(0)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("Deleting ${d.count} post${if (d.count == 1) "" else "s"} for ${d.by.removePrefix("https://")}", style = MaterialTheme.typography.titleSmall, color = Vault.Text)
            Text("in ${left}s · a copy is kept here", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
        }
        Button(onUndo, colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Undo") }
    }
}

@Composable
internal fun BatchCard(b: BatchAsk, now: Long, onDecide: (Boolean) -> Unit) = Card(Vault.AmberEdge, Vault.AmberGround) {
    val left = ((b.expiresAt - now) / 1000).coerceAtLeast(0)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(question(b.text), style = MaterialTheme.typography.titleMedium, color = Vault.Text, modifier = Modifier.weight(1f))
        Text("${left}s", fontFamily = PlexMono, color = Vault.AmberText, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(6.dp))
    Text("${b.by.removePrefix("https://")} asked. A deletion can't be fully taken back; a copy is kept here, so you can post them again.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    Spacer(Modifier.height(14.dp))
    YesNo(onDecide)
}

@Composable
private fun DeletedRow(d: Deleted, onRepost: () -> Unit) = Row(verticalAlignment = Alignment.CenterVertically) {
    Column(Modifier.weight(1f)) {
        Text(d.text.ifBlank { "(no text)" }, style = MaterialTheme.typography.bodyMedium, color = Vault.Text, maxLines = 2, overflow = TextOverflow.Ellipsis)
        Text("${d.kind} · ${ago(d.at)}", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    }
    TextButton(onRepost) { Text("Post again", color = Vault.Teal) }
}

/** Before undoing a site: what it did, and what undoing it will do. */
@Composable
fun UndoSiteSheet(sum: SiteSummary, onUndo: () -> Unit, onClose: () -> Unit) {
    BackHandler { onClose() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            val origin = sum.origin.removePrefix("https://")
            Text("Undo everything $origin did?", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            val did = sum.counts.entries.sortedByDescending { it.value }.joinToString(", ") { (k, n) -> "$n $k${if (n == 1) "" else if (k.endsWith("s")) "" else "s"}" }
            Text(if (sum.total == 0) "It hasn't signed anything yet." else "Since it connected, it signed ${sum.total}: $did.", style = MaterialTheme.typography.bodyMedium, color = Vault.Text)
            Spacer(Modifier.height(8.dp))
            val parts = buildList {
                add("removes its access")
                if (sum.lists.isNotEmpty()) add("puts your ${sum.lists.joinToString(" and ")} back to how ${if (sum.lists.size == 1) "it was" else "they were"} before it changed ${if (sum.lists.size == 1) "it" else "them"}")
                if (sum.deletable > 0) add("deletes the other ${sum.deletable} it posted")
            }
            Text("This ${if (parts.size > 1) parts.dropLast(1).joinToString(", ") + " and " + parts.last() else parts.first()}." + if (sum.deletable > 0) " A deletion can't be fully taken back; $appName keeps copies." else "",
                style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
            Spacer(Modifier.height(20.dp))
            OutlinedButton(onClose, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Cancel", color = Vault.Text) }
            Spacer(Modifier.height(10.dp))
            Button(onUndo, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Amber, Vault.OnAmber)) { Text("Undo everything", fontWeight = FontWeight.SemiBold) }
        }
    }
}

@Composable
private fun ChangeRow(c: Change, onUndo: () -> Unit) = Row(verticalAlignment = Alignment.CenterVertically) {
    Box(Modifier.size(6.dp).background(if (c.held) Vault.Amber else Vault.Teal, CircleShape))
    Spacer(Modifier.width(10.dp))
    Column(Modifier.weight(1f)) {
        Text(c.text, style = MaterialTheme.typography.bodyMedium, color = if (c.undone) Vault.Muted else Vault.Text)
        Text("${c.by.removePrefix("https://")} · ${ago(c.at)}${if (c.undone) " · undone" else ""}", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    }
    if (!c.undone) TextButton(onUndo) { Text("Undo", color = Vault.Teal) }
}

@Composable
private fun Chip(label: String, on: Boolean, modifier: Modifier) = Row(
    modifier.border(1.dp, Vault.Edge, RoundedCornerShape(10.dp)).padding(horizontal = 10.dp, vertical = 10.dp),
    verticalAlignment = Alignment.CenterVertically,
) {
    Box(Modifier.size(8.dp).background(if (on) Vault.Teal else Vault.Field, CircleShape))
    Spacer(Modifier.width(8.dp))
    Text(label, style = MaterialTheme.typography.bodySmall, color = if (on) Vault.Text else Vault.Muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
}

@Composable
private fun Card(edge: Color, ground: Color = Vault.Surface, content: @Composable () -> Unit) =
    Column(Modifier.fillMaxWidth().background(ground, RoundedCornerShape(14.dp)).border(1.dp, edge, RoundedCornerShape(14.dp)).padding(16.dp)) { content() }

@Composable
private fun LogLine(line: Line) = Row {
    val color = when (line.kind) { "approved" -> Vault.Amber; "denied" -> Vault.Danger; "auto" -> Vault.Teal; else -> Vault.Muted }
    Box(Modifier.padding(top = 7.dp).size(6.dp).background(color, CircleShape))
    Spacer(Modifier.width(10.dp))
    Column {
        Text(line.text, style = MaterialTheme.typography.bodyMedium, color = Vault.Text)
        Text(DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(line.ts)), style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    }
}

private fun ago(seconds: Long): String {
    val s = System.currentTimeMillis() / 1000 - seconds
    return when { s < 60 -> "just now"; s < 3600 -> "${s / 60} min ago"; s < 86400 -> "${s / 3600} h ago"; else -> "${s / 86400} d ago" }
}

private fun short(npub: String) = if (npub.length > 20) npub.take(12) + "…" + npub.takeLast(6) else npub


/** On a new device: its code, for one of your devices to scan. */
@Composable
private fun JoinCode(code: String, error: String?, onCancel: () -> Unit) = Page {
    Spacer(Modifier.height(24.dp))
    Text("Sign in with another device", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
    Spacer(Modifier.height(10.dp))
    Text("On your other phone, open $appName, tap your picture, then Add a device, and scan this. It asks for that phone's screen lock.", style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
    Spacer(Modifier.height(24.dp))
    val qr = remember(code) { qrBitmap(code, 720) }
    androidx.compose.foundation.Image(qr.asImageBitmap(), "Join code", Modifier.fillMaxWidth().then(Modifier.aspectRatio(1f)).background(Color.White, RoundedCornerShape(12.dp)).padding(12.dp))
    error?.let { Spacer(Modifier.height(12.dp)); Text(it, color = Vault.Danger, style = MaterialTheme.typography.bodySmall) }
    Spacer(Modifier.weight(1f))
    TextButton(onCancel, Modifier.align(Alignment.CenterHorizontally)) { Text("Cancel", color = Vault.Muted) }
}

private fun qrBitmap(text: String, size: Int): android.graphics.Bitmap {
    val m = com.google.zxing.qrcode.QRCodeWriter().encode(text, com.google.zxing.BarcodeFormat.QR_CODE, size, size)
    val px = IntArray(size * size) { i -> if (m[i % size, i / size]) android.graphics.Color.BLACK else android.graphics.Color.WHITE }
    return android.graphics.Bitmap.createBitmap(px, size, size, android.graphics.Bitmap.Config.ARGB_8888)
}

/** Your keys on this phone: switch between them, or add another. */
@Composable
private fun KeysSheet(current: Phone, onClose: () -> Unit) {
    val accounts = CosignApp.instance.accounts
    BackHandler { onClose() }
    androidx.compose.ui.window.Dialog(onClose) {
        Column(Modifier.background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp)) {
            Text("Your accounts on this phone", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(12.dp))
            for (p in accounts.all.filter { it.isMember || it === current }) {
                TextButton({ accounts.show(p.slot); onClose() }, Modifier.fillMaxWidth(), contentPadding = PaddingValues(0.dp)) {
                    Text((if (p === current) "● " else "○ ") + accountName(p), color = if (p === current) Vault.Teal else Vault.Text, modifier = Modifier.fillMaxWidth())
                }
            }
            Spacer(Modifier.height(8.dp))
            Text("Each account has its own devices, sites and history; adding one doesn't touch the others.", color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(12.dp))
            Button({ accounts.add(); onClose() }, Modifier.fillMaxWidth().height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Add another account") }
        }
    }
}

/** Servers this key doesn't use yet: pick one to add (after this phone's lock). */
@Composable
private fun ServerChoiceSheet(choice: List<cc.aaro.cosign.net.Servers.Server>, status: String?, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var picked by remember { mutableStateOf<cc.aaro.cosign.net.Servers.Server?>(null) }
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) picked?.let(phone::addServer)
    }
    BackHandler { phone.closeServerChoice() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            Text("Add a server", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(8.dp))
            Text("It holds one share of your key, never enough to sign alone. Your key stays the same.", color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(12.dp))
            if (status != null) Text(status, color = Vault.Muted)
            else if (choice.isEmpty()) Text("No other public server found right now.", color = Vault.Muted)
            for (s in choice) TextButton({
                picked = s
                val ask = lockIntent(context, "Add ${s.name}", "Confirm it's you to add a server to your key")
                if (ask == null) phone.lockMissing() else lock.launch(ask)
            }, Modifier.fillMaxWidth(), contentPadding = PaddingValues(0.dp)) {
                Column(Modifier.fillMaxWidth()) {
                    Text(s.name, color = Vault.Teal)
                    Text("Run by ${cc.aaro.cosign.core.Nip19.npub(s.operator).take(12)}…${if (s.version.isNotEmpty()) " · Cosign ${s.version}" else ""}", color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
                }
            }
            Spacer(Modifier.height(12.dp))
            OutlinedButton({ phone.closeServerChoice() }, Modifier.fillMaxWidth().height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Cancel", color = Vault.Text) }
        }
    }
}

/** One device and no paper: a card at the top until there's one or the other. */
@Composable
internal fun PaperCard(phone: Phone) = Card(Vault.AmberEdge, Vault.AmberGround) {
    Text("Make your paper backup", style = MaterialTheme.typography.titleMedium, color = Vault.AmberText)
    Spacer(Modifier.height(4.dp))
    Text("If you lose this phone, you can't get your account back without it. Or add another device.", color = Vault.Text, style = MaterialTheme.typography.bodyMedium)
    PaperButton(phone, "Make it now")
}

/** Right after the key arrives: the paper, once. Skipping is fine. */
@Composable
private fun PaperPrompt(phone: Phone) {
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            Text("Make your paper backup", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            Text("If you lose this phone, you can't get your account back without it. It takes a minute: print it, or keep it in a password manager.",
                style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
            Spacer(Modifier.height(16.dp))
            OutlinedButton({ phone.laterPaper() }, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Later", color = Vault.Text) }
            Spacer(Modifier.height(10.dp))
            PaperButton(phone, "Make it now", filled = true) { phone.laterPaper() }
        }
    }
}

/** Make a paper backup, after this phone's lock. */
@Composable
private fun PaperButton(phone: Phone, text: String, filled: Boolean = false, after: () -> Unit = {}) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) { after(); phone.makePaper() }
    }
    val go = {
        val ask = lockIntent(context, "Make a paper backup", "Confirm it's you to make a backup of your account")
        if (ask == null) phone.lockMissing() else lock.launch(ask)
    }
    if (filled) Button(go, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text(text) }
    else TextButton(go, contentPadding = PaddingValues(0.dp)) { Text(text, color = Vault.Teal) }
}

/** The paper backup: whether there is one, and making one (after this phone's lock). */
@Composable
private fun PaperRow(made: Boolean, status: String?, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) phone.makePaper()
    }
    Column(Modifier.padding(top = 6.dp)) {
        Text(if (made) "Paper backup: made" else "No paper backup yet. If you lose this phone, it's how you get your account back.",
            color = if (made) Vault.Text else Vault.AmberText, style = MaterialTheme.typography.bodyMedium)
        if (status != null) Text(status, color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
        else TextButton({
            val ask = lockIntent(context, "Make a paper backup", "Confirm it's you to make a backup of your account")
            if (ask == null) phone.lockMissing() else lock.launch(ask)
        }, contentPadding = PaddingValues(0.dp)) { Text(if (made) "Make a new one" else "Make a paper backup", color = Vault.Teal) }
    }
}

/** The paper backup's code, shown once: print it, or write it down, and keep it somewhere safe. */
@Composable
private fun PaperSheet(code: String, onClose: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    Box(Modifier.fillMaxSize().background(Vault.Ground)) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp)) {
            Text("Your paper backup", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            Text("Print it or keep it in a password manager, somewhere safe. With it you can get your account back on a new phone, after a wait your other devices can stop. $appName won't show it again.",
                color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(16.dp))
            val qr = remember(code) { qrBitmap(code, 720) }
            androidx.compose.foundation.Image(qr.asImageBitmap(), "Paper backup", Modifier.fillMaxWidth(0.8f).align(Alignment.CenterHorizontally).aspectRatio(1f).background(Color.White, RoundedCornerShape(12.dp)).padding(12.dp))
            Spacer(Modifier.height(12.dp))
            Text(code, fontFamily = PlexMono, color = Vault.Muted, style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.weight(1f))
            // Printing also offers "Save as PDF".
            OutlinedButton({
                androidx.print.PrintHelper(context).apply { scaleMode = androidx.print.PrintHelper.SCALE_MODE_FIT }.printBitmap("$appName backup", qr)
            }, Modifier.fillMaxWidth().height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Print or save the QR", color = Vault.Text) }
            Spacer(Modifier.height(10.dp))
            var copied by remember { mutableStateOf(false) }
            OutlinedButton({ copySecret(context, "$appName backup", code); copied = true }, Modifier.fillMaxWidth().height(48.dp), border = BorderStroke(1.dp, Vault.Line)) {
                Text(if (copied) "Copied" else "Copy to a password manager", color = Vault.Text)
            }
            Text("Keep it in a password manager, not in notes or photos.", color = Vault.Muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
            Spacer(Modifier.height(10.dp))
            Button(onClose, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("I've kept it safe") }
        }
    }
}

/** Copy a secret, marked sensitive so the keyboard and clipboard preview don't show it. */
private fun copySecret(context: android.content.Context, label: String, text: String) {
    val clip = android.content.ClipData.newPlainText(label, text)
    clip.description.extras = android.os.PersistableBundle().apply { putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true) }
    context.getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(clip)
}

/** What's on the clipboard, as text (the paper backup's code, pasted from a password manager). */
private fun pasted(context: android.content.Context): String =
    context.getSystemService(android.content.ClipboardManager::class.java).primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()

/** This phone, being restored from a paper backup. */
@Composable
private fun RestoringScreen(r: cc.aaro.cosign.Restoring, onCancel: () -> Unit) = Page {
    Spacer(Modifier.height(24.dp))
    Text("Restoring your account", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
    Spacer(Modifier.height(16.dp))
    if (!r.failed && r.until == null) CircularProgressIndicator(color = Vault.Teal)
    Text(r.text, color = if (r.failed) Vault.Danger else Vault.Text, style = MaterialTheme.typography.bodyLarge)
    r.until?.let {
        Spacer(Modifier.height(10.dp))
        Text("Ready after ${java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(it * 1000))}. Keep $appName installed; it finishes by itself.",
            color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
    }
    Spacer(Modifier.weight(1f))
    TextButton(onCancel, Modifier.align(Alignment.CenterHorizontally)) { Text(if (r.failed) "Start again" else "Stop restoring", color = Vault.Muted) }
}

/** "It's me": the paper backup being used is yours. Kept for as long as the app runs, by the wait's end. */
internal object RecoveryOk {
    private val ok = androidx.compose.runtime.mutableStateListOf<Long>()
    fun has(until: Long) = until in ok
    fun add(until: Long) { ok += until }
}

/** Your paper backup is being used for another phone. If that isn't you, stop it (with this phone's lock). */
@Composable
internal fun RecoveryCard(name: String, until: Long, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) phone.cancelRecovery()
    }
    Card(Vault.AmberEdge, Vault.AmberGround) {
        Text("Your paper backup is being used", style = MaterialTheme.typography.titleMedium, color = Vault.Amber)
        Spacer(Modifier.height(6.dp))
        Text("$name is getting into your account with your paper backup. If that isn't you, stop it now: someone has your paper.",
            style = MaterialTheme.typography.bodyMedium, color = Vault.Text)
        Spacer(Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton({ RecoveryOk.add(until) }, Modifier.weight(1f).height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("It's me", color = Vault.Text) }
            Button({
                val ask = lockIntent(context, "Stop it", "Confirm it's you to stop your paper backup being used")
                if (ask == null) phone.lockMissing() else lock.launch(ask)
            }, Modifier.weight(1f).height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Danger, Vault.Ground)) { Text("Stop it") }
        }
    }
}

/** This phone's lock, asked for right then; null if it has none. */
@Suppress("DEPRECATION") // BiometricPrompt needs a FragmentActivity; this asks for the same lock
private fun lockIntent(context: android.content.Context, title: String, why: String) =
    context.getSystemService(android.app.KeyguardManager::class.java).let { kg -> if (kg.isDeviceSecure) kg.createConfirmDeviceCredentialIntent(title, why) else null }

/** Reporting another device lost: blocked everywhere at once, after this phone's lock. */
@Composable
private fun ReportLostSheet(d: cc.aaro.cosign.Member, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) phone.confirmReportLost()
    }
    BackHandler { phone.cancelReportLost() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            Text("Report ${d.name} lost?", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            Text("From now on it can't do anything for your account, and what it holds stops working. Your account stays the same.",
                style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
            Spacer(Modifier.height(6.dp))
            Text("If you find it, add it again as a new device.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
            Spacer(Modifier.height(20.dp))
            OutlinedButton({ phone.cancelReportLost() }, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Cancel", color = Vault.Text) }
            Spacer(Modifier.height(10.dp))
            Button({
                val ask = lockIntent(context, "Report ${d.name} lost", "Confirm it's you to remove a device from your account")
                if (ask == null) phone.lockMissing() else lock.launch(ask)
            }, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Danger, Vault.Ground)) { Text("Unlock and report") }
        }
    }
}

/** This phone was reported lost. If it's yours, say so (with its lock); the device that reported it is blocked too. */
@Composable
private fun RemovedSheet(by: String, phone: Phone) {
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            Text("This phone was reported lost", style = MaterialTheme.typography.titleLarge, color = Vault.Danger)
            Spacer(Modifier.height(10.dp))
            Text("$by reported it, so it can't sign any more. If that was a mistake, add this phone again from one of your devices, or restore it from your paper backup.",
                style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
        }
    }
}

/** You scanned a new device's code: add it, after this phone's own lock. */
@Composable
private fun AddDeviceSheet(a: cc.aaro.cosign.AddingDevice, phone: Phone) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val lock = androidx.activity.compose.rememberLauncherForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == android.app.Activity.RESULT_OK) phone.confirmAddDevice()
    }
    BackHandler { phone.cancelAddDevice() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            Text("Add ${a.name} to your account?", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            Text("It gets its own part of your account and can approve things, like this phone. This phone sets it up; nothing ever holds all of your account.",
                style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
            Spacer(Modifier.height(6.dp))
            Text("$appName asks for this phone's lock first.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
            Spacer(Modifier.height(20.dp))
            OutlinedButton({ phone.cancelAddDevice() }, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Don't add", color = Vault.Text) }
            Spacer(Modifier.height(10.dp))
            Button({
                val kg = context.getSystemService(android.app.KeyguardManager::class.java)
                @Suppress("DEPRECATION") // BiometricPrompt needs a FragmentActivity; this asks for the same lock
                val ask = if (kg.isDeviceSecure) kg.createConfirmDeviceCredentialIntent("Add ${a.name}", "Confirm it's you to add a device to your account") else null
                if (ask == null) phone.lockMissing() else lock.launch(ask)
            }, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Unlock and add") }
        }
    }
}
