package cc.aaro.cosign.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import cc.aaro.cosign.Connect
import cc.aaro.cosign.Line
import cc.aaro.cosign.Offer
import cc.aaro.cosign.Phone
import cc.aaro.cosign.Site
import cc.aaro.cosign.Ui
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date

@Composable
fun App(phone: Phone, ui: Ui) {
    var scanning by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxSize().background(Vault.Ground)) {
        when {
            scanning -> {
                BackHandler { scanning = false }
                Box(Modifier.fillMaxSize()) {
                    QrScanner(Modifier.fillMaxSize()) { scanning = false; phone.scanned(it) }
                    TextButton({ scanning = false }, Modifier.align(Alignment.BottomCenter).safeDrawingPadding().padding(24.dp)) { Text("Cancel", color = Vault.Text) }
                }
            }
            ui.offer != null -> JoinPrompt(ui.offer, phone::accept, phone::decline)
            ui.joining != null -> Joining(ui.joining, phone::decline)
            ui.member == null -> Welcome(ui.error) { phone.clearError(); scanning = true }
            else -> Home(phone, ui) { phone.clearError(); scanning = true }
        }
        ui.connect?.let { ConnectSheet(it, phone::confirmConnect, phone::closeConnect) }
    }
}

@Composable
private fun Page(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 24.dp, vertical = 16.dp), content = content)

@Composable
private fun Welcome(error: String?, onScan: () -> Unit) = Page {
    Spacer(Modifier.weight(1f))
    Text("Cosign", style = MaterialTheme.typography.headlineMedium, color = Vault.Text)
    Spacer(Modifier.height(12.dp))
    Text(
        "Your Nostr key, split between your two servers and this phone. Sites sign through your servers; " +
            "this phone is where you connect them, remove them, and approve anything destructive.",
        style = MaterialTheme.typography.bodyLarge, color = Vault.Muted,
    )
    error?.let { Spacer(Modifier.height(16.dp)); Text(it, color = Vault.Danger, style = MaterialTheme.typography.bodyMedium) }
    Spacer(Modifier.weight(1f))
    Button(onScan, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
        Text("Scan your server's code", style = MaterialTheme.typography.labelLarge)
    }
    Spacer(Modifier.height(8.dp))
    Text("It's on your server's page, under “Add your phone”.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted, modifier = Modifier.align(Alignment.CenterHorizontally))
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
private fun JoinPrompt(offer: Offer, onJoin: () -> Unit, onCancel: () -> Unit) = Page {
    Spacer(Modifier.height(24.dp))
    Text("Add this phone?", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
    Spacer(Modifier.height(12.dp))
    Text(short(offer.group.npub), fontFamily = PlexMono, color = Vault.Teal, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(20.dp))
    Text(
        "This phone will hold 1 of ${offer.group.members.size} shares of this key. Any ${offer.group.threshold} of your servers and this phone can sign; none of them alone.",
        color = Vault.Text, style = MaterialTheme.typography.bodyLarge,
    )
    Spacer(Modifier.height(12.dp))
    Text("Almost everything signs without asking. Anything destructive — most of your follows gone, your profile wiped, a pile of deletions — waits for you here.",
        color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
    Spacer(Modifier.weight(1f))
    Button(onJoin, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Add this phone", style = MaterialTheme.typography.labelLarge) }
    Spacer(Modifier.height(8.dp))
    TextButton(onCancel, Modifier.fillMaxWidth()) { Text("Not now", color = Vault.Muted) }
}

/** Connecting a site: the one-tap consent of QRST at its lowest check, then progress. */
@Composable
private fun ConnectSheet(c: Connect, onConnect: () -> Unit, onClose: () -> Unit) {
    BackHandler { onClose() }
    Box(Modifier.fillMaxSize().background(Color(0xCC0B0A09)), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.fillMaxWidth().safeDrawingPadding().padding(12.dp)
                .background(Vault.Surface, RoundedCornerShape(20.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(20.dp)).padding(22.dp),
        ) {
            when (c.stage) {
                Connect.Stage.CONFIRM -> {
                    Text("Let ${c.origin} sign as you?", style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                    Spacer(Modifier.height(10.dp))
                    Text("It gets its own access, through your servers — not your key. Everyday things sign automatically; anything destructive comes to this phone first.",
                        style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
                    Spacer(Modifier.height(6.dp))
                    Text("Remove it here any time. That stops future signing; it doesn't undo what it already signed.",
                        style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
                    Spacer(Modifier.height(20.dp))
                    // Declining is never the weaker control; the affirmative one names the site.
                    OutlinedButton(onClose, Modifier.fillMaxWidth().height(52.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Don't connect", color = Vault.Text) }
                    Spacer(Modifier.height(10.dp))
                    Button(onConnect, Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
                        Text("Connect ${c.origin}", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
                Connect.Stage.WORKING -> Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(22.dp), color = Vault.Teal, strokeWidth = 2.dp)
                    Spacer(Modifier.width(14.dp))
                    Text(c.message ?: "Connecting…", color = Vault.Text)
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

@Composable
private fun Home(phone: Phone, ui: Ui, onScan: () -> Unit) {
    val m = ui.member!!
    var leaving by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() } }

    LazyColumn(Modifier.fillMaxSize().safeDrawingPadding(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Text("Cosign", style = MaterialTheme.typography.labelMedium, color = Vault.Muted)
            Spacer(Modifier.height(4.dp))
            Text(short(m.group.npub), fontFamily = PlexMono, style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (mem in m.group.members) Chip(if (mem.idx == m.idx) "This phone" else mem.name, ui.online[mem.idx] == true, Modifier.weight(1f))
            }
            if (ui.relaysUp == 0) Text("No relay connection. Retrying…", color = Vault.Danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
        }
        item {
            Button(onScan, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
                Text("Connect a site", style = MaterialTheme.typography.labelLarge)
            }
            ui.error?.let { Text(it, color = Vault.Danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp)) }
        }
        items(ui.asks, key = { it.id }) { ask -> AskCard(ask, now) { approve -> phone.decide(ask.id, approve) } }

        item { Heading("Sites that can sign as you") }
        if (ui.sites.isEmpty()) item { Muted("None yet. Tap Connect a site and scan a site's sign-in code.") }
        // One entry per website, with each way it's connected inside.
        items(ui.sites.groupBy { it.origin }.toList(), key = { it.first }) { (origin, grants) ->
            SiteGroup(origin, grants, onRemove = phone::removeSite)
        }

        item { Heading("Recent changes to your lists") }
        if (ui.changes.isEmpty()) item { Muted("Follows, profile, relays, bookmarks… every change shows up here, with Undo.") }
        items(ui.changes.take(12), key = { it.id }) { ChangeRow(it) { phone.undo(it) } }

        item { Heading("On this phone") }
        items(ui.log.take(20)) { LogLine(it) }
        item {
            Spacer(Modifier.height(12.dp))
            Muted("${ui.relaysUp}/${m.group.relays.size} relays · " + if (ui.push != null) "ntfy wakes this phone for approvals" else "no ntfy: approvals arrive while Cosign is running")
            TextButton({ leaving = true }, contentPadding = PaddingValues(0.dp)) { Text("Remove this phone from your key", color = Vault.Danger, style = MaterialTheme.typography.bodySmall) }
        }
    }

    if (leaving) AlertDialog(
        onDismissRequest = { leaving = false },
        title = { Text("Remove this phone?") },
        text = { Text("This deletes the share on this phone. Your servers keep signing everyday things, but nothing destructive can be approved until you set up a new key.") },
        confirmButton = { TextButton({ leaving = false; phone.leave() }) { Text("Delete the share", color = Vault.Danger) } },
        dismissButton = { TextButton({ leaving = false }) { Text("Keep it") } },
        containerColor = Vault.Surface,
    )
}

@Composable private fun Heading(text: String) = Text(text, style = MaterialTheme.typography.titleSmall, color = Vault.Muted, modifier = Modifier.padding(top = 10.dp))
@Composable private fun Muted(text: String) = Text(text, style = MaterialTheme.typography.bodySmall, color = Vault.Muted)

@Composable
private fun AskCard(ask: Ask, now: Long, onDecide: (Boolean) -> Unit) = Card(Vault.AmberEdge, Vault.AmberGround) {
    val left = ((ask.expiresAt - now) / 1000).coerceAtLeast(0)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Approve?", style = MaterialTheme.typography.labelMedium, color = Vault.AmberText, modifier = Modifier.weight(1f))
        Text("${left}s", fontFamily = PlexMono, color = Vault.AmberText, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(4.dp))
    Text(ask.hold, style = MaterialTheme.typography.titleMedium, color = Vault.Text)
    Spacer(Modifier.height(6.dp))
    Text("${ask.app} asked", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    Spacer(Modifier.height(14.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedButton({ onDecide(false) }, Modifier.weight(1f).height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Deny", color = Vault.Text) }
        Button({ onDecide(true) }, Modifier.weight(1f).height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Amber, Vault.OnAmber)) { Text("Approve", fontWeight = FontWeight.SemiBold) }
    }
}

@Composable
private fun SiteGroup(origin: String, grants: List<Site>, onRemove: (Site) -> Unit) = Column(
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
        TextButton({ onRemove(g) }) { Text("Remove", color = Vault.AmberText) }
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
