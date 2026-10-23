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
import cc.aaro.cosign.Kinds
import cc.aaro.cosign.Line
import cc.aaro.cosign.Offer
import cc.aaro.cosign.Phone
import cc.aaro.cosign.Ui
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date

@Composable
fun App(phone: Phone, ui: Ui) {
    var scanning by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxSize().background(Vault.Ground)) {
        when {
            ui.offer != null -> JoinPrompt(ui.offer, phone::accept, phone::decline)
            ui.joining != null -> Joining(ui.joining, phone::decline)
            ui.member == null && scanning -> {
                BackHandler { scanning = false }
                Box(Modifier.fillMaxSize()) {
                    QrScanner(Modifier.fillMaxSize()) { scanning = false; phone.scanned(it) }
                    TextButton({ scanning = false }, Modifier.align(Alignment.BottomCenter).safeDrawingPadding().padding(24.dp)) { Text("Cancel", color = Vault.Text) }
                }
            }
            ui.member == null -> Welcome(ui.error) { phone.clearError(); scanning = true }
            else -> Home(phone, ui)
        }
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
        "Holds one share of your Nostr key. Your two servers sign the everyday things between them; " +
            "anything that matters waits for you to tap Approve here. Lose this phone, or either server, and the other two still work.",
        style = MaterialTheme.typography.bodyLarge, color = Vault.Muted,
    )
    if (error != null) {
        Spacer(Modifier.height(16.dp))
        Text(error, color = Vault.Danger, style = MaterialTheme.typography.bodyMedium)
    }
    Spacer(Modifier.weight(1f))
    Button(onScan, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) {
        Text("Scan your server's code", style = MaterialTheme.typography.labelLarge)
    }
    Spacer(Modifier.height(8.dp))
    Text("It's on the server's page, under “Add your phone”.", style = MaterialTheme.typography.bodySmall, color = Vault.Muted, modifier = Modifier.align(Alignment.CenterHorizontally))
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
    Text("Join this key?", style = MaterialTheme.typography.headlineSmall, color = Vault.Text)
    Spacer(Modifier.height(12.dp))
    Text(short(offer.group.npub), fontFamily = PlexMono, color = Vault.Teal, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(20.dp))
    val names = offer.group.members.map { if (it.idx == offer.idx) "this phone" else it.name }
    Text(
        "This phone will hold 1 of ${offer.group.members.size} shares. Any ${offer.group.threshold} of " +
            names.joinToString(", ") + " can sign; no one of them can sign alone.",
        color = Vault.Text, style = MaterialTheme.typography.bodyLarge,
    )
    Spacer(Modifier.height(12.dp))
    Text(
        "Notes, reactions and logins are signed by the servers without asking. Anything else — your profile, follow list, deletions, DMs — asks you here first.",
        color = Vault.Muted, style = MaterialTheme.typography.bodyMedium,
    )
    Spacer(Modifier.weight(1f))
    Button(onJoin, Modifier.fillMaxWidth().height(56.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Join", style = MaterialTheme.typography.labelLarge) }
    Spacer(Modifier.height(8.dp))
    TextButton(onCancel, Modifier.fillMaxWidth()) { Text("Not now", color = Vault.Muted) }
}

@Composable
private fun Home(phone: Phone, ui: Ui) {
    val m = ui.member!!
    var leaving by remember { mutableStateOf(false) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() } }

    LazyColumn(Modifier.fillMaxSize().safeDrawingPadding(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Text("Cosign", style = MaterialTheme.typography.labelMedium, color = Vault.Muted)
            Spacer(Modifier.height(4.dp))
            Text(short(m.group.npub), fontFamily = PlexMono, style = MaterialTheme.typography.titleLarge, color = Vault.Text)
            Text("1 of ${m.group.members.size} shares · any ${m.group.threshold} sign", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (mem in m.group.members) {
                    val label = if (mem.idx == m.idx) "This phone" else mem.name
                    Chip(label, ui.online[mem.idx] == true, Modifier.weight(1f))
                }
            }
            if (ui.relaysUp == 0) {
                Spacer(Modifier.height(8.dp))
                Text("No relay connection. Retrying…", color = Vault.Danger, style = MaterialTheme.typography.bodySmall)
            }
        }
        if (ui.asks.isEmpty()) {
            item {
                Card(Vault.Edge) {
                    Text("Nothing waiting", style = MaterialTheme.typography.titleSmall, color = Vault.Text)
                    Spacer(Modifier.height(4.dp))
                    Text("Your servers sign notes, reactions and logins without asking. Anything else will appear here, and as a notification.",
                        style = MaterialTheme.typography.bodyMedium, color = Vault.Muted)
                }
            }
        }
        items(ui.asks, key = { it.id }) { ask -> AskCard(ask, now) { approve -> phone.decide(ask.id, approve) } }
        item { Text("Activity", style = MaterialTheme.typography.titleSmall, color = Vault.Muted, modifier = Modifier.padding(top = 8.dp)) }
        if (ui.log.isEmpty()) item { Text("Nothing yet.", color = Vault.Muted, style = MaterialTheme.typography.bodySmall) }
        items(ui.log) { LogLine(it) }
        item {
            Spacer(Modifier.height(16.dp))
            Text("${ui.relaysUp}/${m.group.relays.size} relays", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
            TextButton({ leaving = true }, contentPadding = PaddingValues(0.dp)) { Text("Leave this group", color = Vault.Danger, style = MaterialTheme.typography.bodySmall) }
        }
    }

    if (leaving) AlertDialog(
        onDismissRequest = { leaving = false },
        title = { Text("Leave this group?") },
        text = { Text("This deletes the share on this phone. The two servers can still sign everyday things, but nothing that needs the phone until you set up a new key.") },
        confirmButton = { TextButton({ leaving = false; phone.leave() }) { Text("Delete the share", color = Vault.Danger) } },
        dismissButton = { TextButton({ leaving = false }) { Text("Keep it") } },
        containerColor = Vault.Surface,
    )
}

@Composable
private fun AskCard(ask: Ask, now: Long, onDecide: (Boolean) -> Unit) = Card(Vault.AmberEdge, Vault.AmberGround) {
    val left = ((ask.expiresAt - now) / 1000).coerceAtLeast(0)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Sign a ${Kinds.name(ask.event.kind)}?", style = MaterialTheme.typography.titleMedium, color = Vault.Text, modifier = Modifier.weight(1f))
        Text("${left}s", fontFamily = PlexMono, color = Vault.AmberText, style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(6.dp))
    Text(Kinds.describe(ask.event), style = MaterialTheme.typography.bodyMedium, color = Vault.AmberText, maxLines = 6, overflow = TextOverflow.Ellipsis)
    Spacer(Modifier.height(6.dp))
    Text("${ask.app} asked, through ${ask.via}", style = MaterialTheme.typography.bodySmall, color = Vault.Muted)
    Spacer(Modifier.height(14.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedButton({ onDecide(false) }, Modifier.weight(1f).height(48.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Deny", color = Vault.Text) }
        Button({ onDecide(true) }, Modifier.weight(1f).height(48.dp), colors = ButtonDefaults.buttonColors(Vault.Amber, Vault.OnAmber)) { Text("Approve", fontWeight = FontWeight.SemiBold) }
    }
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

private fun short(npub: String) = if (npub.length > 20) npub.take(12) + "…" + npub.takeLast(6) else npub
