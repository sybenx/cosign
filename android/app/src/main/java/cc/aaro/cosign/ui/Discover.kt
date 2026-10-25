package cc.aaro.cosign.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.CheckCircle
import cc.aaro.cosign.Nip05
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withLink
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import cc.aaro.cosign.CosignApp
import cc.aaro.cosign.Notice
import cc.aaro.cosign.People
import cc.aaro.cosign.Person
import cc.aaro.cosign.Phone
import cc.aaro.cosign.PlaceCard
import cc.aaro.cosign.Ref
import cc.aaro.cosign.Social
import cc.aaro.cosign.Startup
import cc.aaro.cosign.Translate
import cc.aaro.cosign.Ui
import cc.aaro.cosign.appName
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.parentOf
import cc.aaro.cosign.shortNpub
import kotlinx.coroutines.delay

// The home screen, laid out like a search app: a search box, a bell, your picture (which
// opens your account: devices, connected sites, backup; how it works is under Advanced), at most one card that needs you, and a
// Discover feed. No posting, no replies, no zaps: you can like a note and follow someone.

private sealed class Route {
    data object Account : Route()
    data object Bell : Route()
    data object Search : Route()
    data class Thread(val id: String, val reply: Boolean = false) : Route()
    data class Profile(val pubkey: String) : Route()
}

@Composable
fun Discover(phone: Phone, ui: Ui, onScan: () -> Unit) {
    val social = remember(phone) { Social.of(phone) }
    val stack = remember { mutableStateListOf<Route>() }
    val feedState = rememberLazyListState()
    val open: (Route) -> Unit = { stack.add(it) }
    val back: () -> Unit = { stack.removeAt(stack.lastIndex) }
    if (stack.isNotEmpty()) BackHandler(onBack = back)
    // Read on open and when you come back to it; nothing in between.
    LifecycleEventEffect(Lifecycle.Event.ON_START) { social.loadFeed(); social.loadNotices() }

    // A note's pictures, full screen, over everything else.
    var viewing by remember { mutableStateOf<Pair<List<String>, Int>?>(null) }
    val nav = Nav(open = open, back = back, social = social) { urls, i -> viewing = urls to i }
    when (val top = stack.lastOrNull()) {
        null -> Home(phone, ui, social, feedState, nav)
        Route.Account -> AccountScreen(phone, ui, onScan, onProfile = { ui.member?.group?.groupX?.let { nav.profile(it) } }, onBack = back)
        Route.Bell -> BellScreen(phone, ui, social, nav)
        Route.Search -> SearchScreen(social, nav)
        is Route.Thread -> ThreadScreen(top.id, social, nav, top.reply)
        is Route.Profile -> ProfileScreen(top.pubkey, social, nav)
    }

    viewing?.let { (urls, i) -> ImageViewer(urls, i) { viewing = null } }
    VideoFullScreen()

    social.held.collectAsState().value?.let { h ->
        AlertDialog(
            onDismissRequest = { social.decideHeld(false) },
            title = { Text(question(h.what)) },
            text = { Text("Your account asks you first before anything like this.") },
            confirmButton = { TextButton({ social.decideHeld(true) }) { Text("Yes", color = Vault.Amber) } },
            dismissButton = { TextButton({ social.decideHeld(false) }) { Text("Don't") } },
            containerColor = Vault.Surface,
        )
    }
    val message by social.message.collectAsState()
    message?.let { text ->
        LaunchedEffect(text) { delay(4500); social.message.value = null }
        Box(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp), contentAlignment = Alignment.BottomCenter) {
            Text(text, color = Vault.Text, style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.background(Vault.Edge, RoundedCornerShape(10.dp)).padding(horizontal = 16.dp, vertical = 12.dp))
        }
    }
}

private class Nav(val open: (Route) -> Unit, val back: () -> Unit, val social: Social, val pictures: (List<String>, Int) -> Unit = { _, _ -> }) {
    fun thread(id: String) = open(Route.Thread(id))
    /** Open the post with the reply box ready. */
    fun reply(id: String) = open(Route.Thread(id, reply = true))
    fun profile(pk: String) = open(Route.Profile(pk))
    fun search(q: String) { social.search(q); open(Route.Search) }
}

// --- Home ------------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Home(phone: Phone, ui: Ui, social: Social, state: LazyListState, nav: Nav) {
    val feed by social.feed.collectAsState()
    val people by People.known.collectAsState()
    val liked by social.liked.collectAsState()
    val notices by social.notices.collectAsState()
    val seen by social.seenAt.collectAsState()
    val videos by social.videos.collectAsState()
    val me = ui.member!!.group.groupX
    LaunchedEffect(me) { People.want(listOf(me)) }
    val muted by social.muted.collectAsState()
    val dismissed by social.dismissed.collectAsState()
    val snoozed by social.snoozed.collectAsState()
    val mixed = remember(feed.notes, videos, muted, dismissed, snoozed) {
        mix(feed.notes.filter { it.pubkey !in muted && it.id !in dismissed && !social.snoozedNow(it.pubkey) }, videos)
    }
    // How far down you've looked, in notes: a video that comes late goes below it.
    val notesNow by androidx.compose.runtime.rememberUpdatedState(feed.notes)
    LaunchedEffect(state) {
        snapshotFlow { state.layoutInfo.visibleItemsInfo.lastOrNull()?.key }.collect { key ->
            val i = notesNow.indexOfFirst { it.id == key }
            if (i > social.lookedAt) social.lookedAt = i
        }
    }
    val context = LocalContext.current
    LaunchedEffect(Unit) { Startup.mark("home composed", once = false) }
    if (mixed.isNotEmpty()) LaunchedEffect(Unit) { androidx.compose.runtime.withFrameNanos { }; Startup.mark("first cards painted", once = false); social.painted.complete(Unit) }

    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            // The name: back to the top of the feed; already there, refresh it (as pulling down does).
            val scope = rememberCoroutineScope()
            Text(appName, style = MaterialTheme.typography.titleLarge, color = Vault.Text, modifier = Modifier.weight(1f).wrapContentWidth(Alignment.Start)
                .clip(RoundedCornerShape(8.dp)).clickable(onClickLabel = "Back to the top") {
                    if (state.firstVisibleItemIndex == 0 && state.firstVisibleItemScrollOffset == 0) { social.loadFeed(force = true); social.loadNotices(force = true) }
                    else scope.launch {
                        // From far down, jump most of the way first, so the smooth part is short.
                        if (state.firstVisibleItemIndex > 6) state.scrollToItem(6)
                        state.animateScrollToItem(0)
                    }
                }.padding(horizontal = 4.dp, vertical = 2.dp))
            val waiting = ui.asks.size + ui.batchAsks.size
            val fresh = notices.list.count { it.event.createdAt > seen }
            IconButton({ nav.open(Route.Bell) }) {
                Box {
                    Icon(Icons.Outlined.Notifications, "Notifications", tint = Vault.Text)
                    if (waiting + fresh > 0) Box(Modifier.align(Alignment.TopEnd).offset(x = 3.dp, y = (-3).dp).size(9.dp)
                        .background(if (waiting > 0) Vault.Amber else Vault.Teal, CircleShape))
                }
            }
            Spacer(Modifier.width(4.dp))
            Avatar(people[me], me, 34, Modifier.clickable { nav.open(Route.Account) }, "Your account")
        }
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp).fillMaxWidth().height(52.dp)
                .background(Vault.Surface, RoundedCornerShape(26.dp)).border(1.dp, Vault.Edge, RoundedCornerShape(26.dp))
                .clickable { social.clearSearch(); nav.open(Route.Search) }.padding(horizontal = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Filled.Search, null, tint = Vault.Muted)
            Spacer(Modifier.width(12.dp))
            Text("Search people, posts, #tags", color = Vault.Muted, style = MaterialTheme.typography.bodyLarge)
        }

        PullToRefreshBox(feed.loading && feed.notes.isNotEmpty(), { social.loadFeed(force = true); social.loadNotices(force = true) }, Modifier.fillMaxSize()) {
            LazyColumn(Modifier.fillMaxSize(), state = state, contentPadding = PaddingValues(bottom = 24.dp)) {
                item(key = "needs") { NeedsYou(phone, ui, social) { nav.open(Route.Bell) } }
                ui.error?.let { e -> item(key = "error") { Text(e, color = Vault.Danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp)) } }
                if (feed.notes.isEmpty() && (feed.loading || feed.at == 0L && !feed.failed)) item(key = "loading") {
                    Box(Modifier.fillMaxWidth().padding(40.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Vault.Teal) }
                }
                if (feed.failed) item(key = "failed") {
                    Column(Modifier.padding(24.dp)) {
                        Text("Discover isn't answering right now.", color = Vault.Text)
                        TextButton({ social.loadFeed(force = true) }, contentPadding = PaddingValues(0.dp)) { Text("Try again", color = Vault.Teal) }
                    }
                }
                if (feed.notes.isNotEmpty()) item(key = "title") {
                    Text("Discover", style = MaterialTheme.typography.titleSmall, color = Vault.Muted, modifier = Modifier.padding(start = 20.dp, top = 8.dp, bottom = 4.dp))
                }
                items(mixed, key = { if (it is Event) it.id else "place:" + (it as PlaceCard).id }) { item ->
                    if (item is PlaceCard) VideoCard(item) { openInBrowser(context, item.url) }
                    else (item as Event).let { n -> NoteCard(n, people, n.id in liked, nav, onLike = { social.like(n) }, maxLines = 12) }
                    HorizontalDivider(color = Vault.Edge)
                }
                if (feed.notes.isNotEmpty()) item(key = "end") {
                    LaunchedEffect(feed.notes.size) { social.loadMore() }
                    Text(if (feed.loading) "Loading…" else if (!feed.more) "That's all for now." else "",
                        color = Vault.Muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(20.dp))
                    feed.source?.let { Text("Discover from ${it.removePrefix("wss://").substringBefore('/')}", color = Vault.Field, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 20.dp)) }
                }
            }
        }
    }
}

/** Notes, with a place's cards between them: from [Social.Videos.start] on, one every 4 to 6 notes, never two together. */
private fun mix(notes: List<Event>, v: Social.Videos): List<Any> {
    if (v.cards.isEmpty() || v.start < 0) return notes
    val out = ArrayList<Any>(notes.size + v.cards.size)
    var next = v.start; var shown = 0
    notes.forEachIndexed { i, n ->
        if (i == next && shown < v.cards.size) { out += v.cards[shown]; next += 4 + shown % 3; shown++ }
        out += n
    }
    return out
}

/** A video from a place you're signed in to: a big picture with its length, the title, the channel, and where it's from. */
@Composable
private fun VideoCard(c: PlaceCard, onOpen: () -> Unit) = Column(Modifier.fillMaxWidth().clickable(onClick = onOpen).padding(horizontal = 16.dp, vertical = 12.dp)) {
    // No thumbnail: a plain card, the length beside the title instead.
    if (c.thumb != null) {
        Box(Modifier.fillMaxWidth().aspectRatio(16f / 9f).clip(RoundedCornerShape(12.dp))) {
            NetImage(c.thumb, Modifier.fillMaxSize(), 1080, description = c.title)
            c.duration?.let { d ->
                Text(length(d), color = Color.White, style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.align(Alignment.BottomEnd).padding(8.dp).background(Color(0xCC000000), RoundedCornerShape(4.dp)).padding(horizontal = 6.dp, vertical = 2.dp))
            }
        }
        Spacer(Modifier.height(10.dp))
    }
    Text(c.title, color = Vault.Text, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyLarge, maxLines = 2, overflow = TextOverflow.Ellipsis)
    Spacer(Modifier.height(4.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(c.label, color = Vault.Teal, style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.border(1.dp, Vault.TealEdge, RoundedCornerShape(4.dp)).padding(horizontal = 5.dp, vertical = 1.dp))
        Spacer(Modifier.width(8.dp))
        Text(c.channel + if (c.thumb == null && c.duration != null) " · ${length(c.duration)}" else "", color = Vault.Muted, style = MaterialTheme.typography.bodySmall,
            maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

private fun length(s: Int) = if (s >= 3600) "%d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60) else "%d:%02d".format(s / 60, s % 60)

/**
 * Open a page in a Custom Tab, inside this app, when the browser has them. These two extras
 * are what androidx.browser's CustomTabsIntent sets; any other browser just opens the page.
 */
private fun openInBrowser(context: android.content.Context, url: String) {
    val i = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))
    i.putExtras(android.os.Bundle().apply { putBinder("android.support.customtabs.extra.SESSION", null) })
    i.putExtra("android.support.customtabs.extra.TOOLBAR_COLOR", android.graphics.Color.rgb(0x13, 0x11, 0x0F))
    try { context.startActivity(i) } catch (_: android.content.ActivityNotFoundException) {}
}

/** At most one card: the thing that needs you most. The rest are behind the bell. */
@Composable
private fun NeedsYou(phone: Phone, ui: Ui, social: Social, onMore: () -> Unit) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    val counting = ui.asks.isNotEmpty() || ui.batchAsks.isNotEmpty() || ui.deleting.isNotEmpty()
    if (counting) LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() } }
    val cards = needs(phone, ui)
    // Another key of yours with something waiting.
    val others = CosignApp.instance.accounts.all.filter { it !== phone }.map { it to it.ui.collectAsState().value }
        .filter { (_, u) -> u.asks.isNotEmpty() || u.batchAsks.isNotEmpty() }
    if (cards.isEmpty() && others.isEmpty()) return
    Column(Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
        cards.firstOrNull()?.let { NeedCard(it, phone, now) }
        if (cards.size > 1) TextButton(onMore, contentPadding = PaddingValues(0.dp)) { Text("${cards.size - 1} more waiting for you", color = Vault.AmberText) }
        for ((p, u) in others) TextButton({ CosignApp.instance.accounts.show(p.slot) }, contentPadding = PaddingValues(0.dp)) {
            Text("${p.label}: ${u.asks.size + u.batchAsks.size} waiting for you. Switch", color = Vault.AmberText, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** What needs you, most pressing first. */
private sealed class Need {
    data class Approve(val ask: cc.aaro.cosign.Ask) : Need()
    data class Batch(val b: cc.aaro.cosign.BatchAsk) : Need()
    data class Deleting(val d: cc.aaro.cosign.Deleting) : Need()
    data class Recovery(val name: String, val until: Long) : Need()
    data class Future(val f: cc.aaro.cosign.Future) : Need()
    data object Paper : Need()
}

private fun needs(phone: Phone, ui: Ui): List<Need> = buildList {
    ui.asks.forEach { add(Need.Approve(it)) }
    ui.batchAsks.forEach { add(Need.Batch(it)) }
    ui.deleting.forEach { add(Need.Deleting(it)) }
    ui.recovery?.let { if (!RecoveryOk.has(it.second)) add(Need.Recovery(it.first, it.second)) }
    ui.future.forEach { add(Need.Future(it)) }
    if (phone.needsPaper) add(Need.Paper)
}

@Composable
private fun NeedCard(n: Need, phone: Phone, now: Long) = when (n) {
    is Need.Approve -> AskCard(n.ask, now) { approve -> phone.decide(n.ask.id, approve) }
    is Need.Batch -> BatchCard(n.b, now) { approve -> phone.decideBatch(n.b.batch, approve) }
    is Need.Deleting -> DeletingCard(n.d, now) { phone.cancelDeletion(n.d.batch) }
    is Need.Recovery -> RecoveryCard(n.name, n.until, phone)
    is Need.Future -> FutureCard(n.f) { phone.removeFuture(n.f) }
    Need.Paper -> PaperCard(phone)
}

// --- Notes -------------------------------------------------------------------------------

@Composable
private fun NoteCard(n: Event, people: Map<String, Person>, liked: Boolean, nav: Nav, onLike: () -> Unit, maxLines: Int = Int.MAX_VALUE, indent: Int = 0, lit: Boolean = false,
                     onReply: (() -> Unit)? = null) {
    // A repost: the post it shares, under a line saying who shared it.
    if (n.kind == 6) {
        val inner = remember(n.id) { nav.social.reposted(n) } ?: return
        val liked2 by nav.social.liked.collectAsState()
        Column {
            Row(Modifier.padding(start = 68.dp, top = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Glyphs.repost, null, tint = Vault.Muted, modifier = Modifier.size(14.dp))
                Text("  ${people[n.pubkey]?.shown ?: shortNpub(n.pubkey)} reposted", color = Vault.Muted, style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            NoteCard(inner, people, inner.id in liked2, nav, onLike = { nav.social.like(inner) }, maxLines = maxLines)
        }
        return
    }
    val author = people[n.pubkey]
    // Translated by your LibreTranslate, if it was in another language; the original a tap away.
    val translations by nav.social.translations.collectAsState()
    val tr = translations[n.id]?.takeIf { it.from != null }
    var original by remember(n.id) { mutableStateOf(false) }
    val body = remember(n.id, tr, original) { Body.of(n, if (tr != null && !original) tr.text else n.content) }
    Row(
        Modifier.fillMaxWidth().background(if (lit) Vault.TealGround else Color.Transparent)
            .clickable { nav.thread(n.id) }.padding(start = 16.dp + (indent * 14).dp, end = 16.dp, top = 12.dp, bottom = 4.dp),
    ) {
        Avatar(author, n.pubkey, if (indent > 0) 32 else 40, Modifier.clickable { nav.profile(n.pubkey) })
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Box(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(end = 32.dp).align(Alignment.CenterStart), verticalAlignment = Alignment.CenterVertically) {
                    Text(author?.shown ?: shortNpub(n.pubkey), color = Vault.Text, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false).clickable { nav.profile(n.pubkey) })
                    Text("  ${since(n.createdAt)}", color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
                }
                if (n.pubkey != nav.social.me) Box(Modifier.align(Alignment.CenterEnd)) { NoteMenu(n, author?.shown ?: shortNpub(n.pubkey), nav.social) }
            }
            val to = remember(n.id) { n.tags.lastOrNull { it.size > 1 && it[0] == "p" }?.get(1) }
            LaunchedEffect(n.id) { People.want(body.mentions + listOfNotNull(to)) }
            if (indent == 0 && parentOf(n) != null) {
                Text("Replying to ${to?.let { people[it]?.shown ?: shortNpub(it) } ?: "a note"}", color = Vault.Muted, style = MaterialTheme.typography.bodySmall)
            }
            val text = remember(body, people.size) { body.annotated(people, nav) }
            if (text.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(text, color = Vault.Text, style = MaterialTheme.typography.bodyMedium, maxLines = maxLines, overflow = TextOverflow.Ellipsis)
            }
            tr?.let { t ->
                Text("Translated from ${Translate.name(t.from) ?: "another language"} · " + if (original) "Show translation" else "Show original",
                    color = Vault.Muted, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 4.dp).clickable { original = !original })
            }
            // In a list, one picture, no taller than it is wide; a thread shows them all, whole.
            val full = maxLines == Int.MAX_VALUE
            // A tap on a picture opens it full screen (and not the thread); a video plays where it is.
            val urls = remember(body) { body.images.map { it.url } }
            body.media.take(if (full) 4 else 1).forEach { m ->
                Spacer(Modifier.height(8.dp))
                when (m) {
                    is Body.Img -> NetImage(m.url, Modifier.fillMaxWidth().aspectRatio(m.ratio.coerceIn(if (full) 0.6f else 1f, 2.2f)).clip(RoundedCornerShape(12.dp))
                        .clickable { nav.pictures(urls, urls.indexOf(m.url).coerceAtLeast(0)) }, 1080, description = "Picture")
                    is Body.Vid -> VideoCard(m.v)
                }
            }
            if (!full && body.media.size > 1) Text("+${body.media.size - 1} more", color = Vault.Muted, style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp).clickable { if (body.media.drop(1).all { it is Body.Img }) nav.pictures(urls, 1) else nav.thread(n.id) })
            // Like and reply, as plain icons (an IconButton each costs a visible frame on a slow phone).
            Row(Modifier.offset(x = (-9).dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(if (liked) Glyphs.heartOn else Glyphs.heart, if (liked) "Liked" else "Like", tint = if (liked) Vault.Amber else Vault.Muted,
                    modifier = Modifier.size(40.dp).clip(CircleShape).clickable(onClick = onLike).padding(10.dp))
                Icon(Glyphs.reply, "Reply", tint = Vault.Muted,
                    modifier = Modifier.size(40.dp).clip(CircleShape).clickable { onReply?.invoke() ?: nav.reply(n.id) }.padding(10.dp))
            }
        }
    }
}

/** "⋯": not interested in this note, or mute its author (on this phone and in your mute list). */
@Composable
private fun NoteMenu(n: Event, name: String, social: Social) = Box {
    var open by remember { mutableStateOf(false) }
    var reporting by remember { mutableStateOf(false) }
    // A plain icon on every card (an IconButton each costs a visible frame on a slow phone); the menu only once it's open.
    Icon(Icons.Filled.MoreVert, "More", tint = Vault.Muted, modifier = Modifier.size(28.dp).clip(CircleShape).clickable { open = true }.padding(5.dp))
    if (open) DropdownMenu(true, { open = false }, containerColor = Vault.Surface) {
        DropdownMenuItem({ Text("Not interested", color = Vault.Text) }, { open = false; social.notInterested(n) })
        DropdownMenuItem({ Text("Mute $name", color = Vault.Text, maxLines = 1, overflow = TextOverflow.Ellipsis) }, {
            open = false; social.mute(n.pubkey); social.message.value = "You won't see $name any more."
        })
        DropdownMenuItem({ Text("Report…", color = Vault.Danger) }, { open = false; reporting = true })
    }
    if (reporting) ReportDialog(name, onClose = { reporting = false }) { reason -> reporting = false; social.report(n, reason) }
}

/** Why you're reporting it: one tap sends it, and the post goes away. */
@Composable
private fun ReportDialog(name: String, onClose: () -> Unit, onReport: (String) -> Unit) = AlertDialog(
    onDismissRequest = onClose,
    title = { Text("Report this post?") },
    text = {
        Column {
            Text("It's hidden for you at once. What's wrong with it?", color = Vault.Muted, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            for ((reason, label) in listOf("spam" to "Spam", "nudity" to "Nudity or sexual content", "profanity" to "Hateful or abusive",
                "illegal" to "Illegal", "impersonation" to "Pretending to be someone they're not", "other" to "Something else")) {
                Text(label, color = Vault.Text, style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { onReport(reason) }.padding(vertical = 10.dp, horizontal = 4.dp))
            }
        }
    },
    confirmButton = {},
    dismissButton = { TextButton(onClose) { Text("Cancel") } },
    containerColor = Vault.Surface,
)

/** A note's text, cut up: pictures apart, mentions and #tags made tappable. */
private class Body(val parts: List<Part>, val media: List<Media>, val mentions: List<String>) {
    val images get() = media.filterIsInstance<Img>()
    sealed class Part {
        data class Plain(val s: String) : Part()
        data class Link(val url: String) : Part()
        data class Mention(val pubkey: String) : Part()
        data class Quote(val id: String) : Part()
        data class Tag(val tag: String) : Part()
    }
    sealed class Media
    data class Img(val url: String, val ratio: Float) : Media()
    data class Vid(val v: VideoRef) : Media()

    fun annotated(people: Map<String, Person>, nav: Nav): AnnotatedString = buildAnnotatedString {
        val style = TextLinkStyles(SpanStyle(color = Vault.Teal))
        for (p in parts) when (p) {
            is Part.Plain -> append(p.s)
            is Part.Link -> withLink(LinkAnnotation.Url(p.url, style)) { append(p.url.removePrefix("https://").let { if (it.length > 40) it.take(38) + "…" else it }) }
            is Part.Mention -> withLink(LinkAnnotation.Clickable(p.pubkey, style) { nav.profile(p.pubkey) }) { append("@" + (people[p.pubkey]?.shown ?: shortNpub(p.pubkey))) }
            is Part.Quote -> withLink(LinkAnnotation.Clickable(p.id, style) { nav.thread(p.id) }) { append("↪ quoted note") }
            is Part.Tag -> withLink(LinkAnnotation.Clickable(p.tag, style) { nav.search("#" + p.tag) }) { append("#" + p.tag) }
        }
    }.let { if (it.text.isBlank()) AnnotatedString("") else it }

    companion object {
        private val TOKEN = Regex("(https?://[^\\s<>\"]+)|nostr:((?:npub|nprofile|note|nevent)1[02-9ac-hj-np-z]+)|(?<=^|\\s)#([\\p{L}\\p{N}_]{1,40})")
        private val IMAGE = Regex("\\.(jpe?g|png|gif|webp|avif)(\\?.*)?$", RegexOption.IGNORE_CASE)
        private val VIDEO = Regex("\\.(mp4|webm|mov|m4v|m3u8)(\\?.*)?$", RegexOption.IGNORE_CASE)
        private val BREAKS = Regex("[ \\t]*\\n[ \\t\\n]*\\n[ \\t\\n]*")

        fun of(e: Event, content: String = e.content): Body {
            // NIP-92 imeta (and NIP-71 video events): each file's shape, type, picture and length.
            val meta = e.tags.filter { it.isNotEmpty() && it[0] == "imeta" }.mapNotNull { t ->
                val f = t.drop(1).associate { it.substringBefore(' ') to it.substringAfter(' ') }
                f["url"]?.let { it to f }
            }.toMap()
            fun ratioOf(url: String) = meta[url]?.get("dim")?.split('x')?.mapNotNull { it.toFloatOrNull() }?.takeIf { it.size == 2 && it[1] > 0 }?.let { it[0] / it[1] }
            fun isVideo(url: String) = VIDEO.containsMatchIn(url) || meta[url]?.get("m")?.startsWith("video/") == true
            fun video(url: String) = Vid(VideoRef(url, (meta[url]?.get("image") ?: meta[url]?.get("thumb"))?.takeIf { it.startsWith("https://") },
                ratioOf(url) ?: (16f / 9f), meta[url]?.get("duration")?.toFloatOrNull()?.toInt()))
            val parts = ArrayList<Part>(); val images = ArrayList<Media>(); val mentions = ArrayList<String>()
            var at = 0
            val text = content.trim()
            for (m in TOKEN.findAll(text)) {
                if (m.range.first > at) parts += Part.Plain(text.substring(at, m.range.first))
                at = m.range.last + 1
                val url = m.groups[1]?.value?.trimEnd('.', ',', ')', '!', '?')
                val ref = m.groups[2]?.value
                val tag = m.groups[3]?.value
                when {
                    url != null && isVideo(url) -> images += video(url)
                    url != null && IMAGE.containsMatchIn(url) -> images += Img(url, ratioOf(url) ?: 1.5f)
                    url != null -> parts += Part.Link(url)
                    ref != null -> when (val r = Ref.parse(ref)) {
                        is Ref.Profile -> { parts += Part.Mention(r.pubkey); mentions += r.pubkey }
                        is Ref.Note -> parts += Part.Quote(r.id)
                        null -> parts += Part.Plain(m.value)
                    }
                    tag != null -> parts += Part.Tag(tag)
                }
            }
            if (at < text.length) parts += Part.Plain(text.substring(at))
            // A video event (NIP-71) names its file only in imeta; so may any note.
            for ((url, f) in meta) if (f["m"]?.startsWith("video/") == true && images.none { it is Vid && it.v.url == url }) images += video(url)
            // Media links are pulled out of the text: tidy the line breaks they leave behind
            // (the text on either side of one is one stretch now).
            val joined = ArrayList<Part>()
            for (p in parts) { val last = joined.lastOrNull(); if (p is Part.Plain && last is Part.Plain) joined[joined.lastIndex] = Part.Plain(last.s + p.s) else joined += p }
            parts.clear(); parts += joined
            val tidy = parts.mapIndexed { i, p ->
                if (p !is Part.Plain) p else Part.Plain(p.s.replace(BREAKS, "\n\n").let { s -> if (i == 0) s.trimStart() else s }.let { s -> if (i == parts.lastIndex) s.trimEnd() else s })
            }
            return Body(tidy, images.take(4), mentions)
        }
    }
}

@Composable
internal fun Avatar(p: Person?, pubkey: String, size: Int, modifier: Modifier = Modifier, description: String? = null) {
    val hue = remember(pubkey) { (pubkey.take(6).toLongOrNull(16) ?: 0L) % 360 }
    NetImage(p?.picture, modifier.size(size.dp).clip(CircleShape), size * 3, description = description ?: p?.shown) {
        Box(Modifier.fillMaxSize().background(Color.hsl(hue.toFloat(), 0.35f, 0.35f)), contentAlignment = Alignment.Center) {
            // No profile (yet): a figure, not a letter of an npub.
            if (p?.name == null) Icon(Icons.Filled.Person, null, tint = Vault.Text, modifier = Modifier.size((size * 0.6).dp))
            else Text(p.shown.take(1).uppercase(), color = Vault.Text, style = if (size > 50) MaterialTheme.typography.headlineSmall else MaterialTheme.typography.bodyMedium)
        }
    }
}

private fun since(t: Long): String {
    val s = System.currentTimeMillis() / 1000 - t
    return when {
        s < 60 -> "now"; s < 3600 -> "${s / 60}m"; s < 86400 -> "${s / 3600}h"; s < 7 * 86400 -> "${s / 86400}d"
        else -> java.text.SimpleDateFormat("d MMM", java.util.Locale.getDefault()).format(java.util.Date(t * 1000))
    }
}

@Composable
private fun TopBar(title: String, nav: Nav) = Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
    IconButton(nav.back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Vault.Text) }
    Text(title, style = MaterialTheme.typography.titleMedium, color = Vault.Text, maxLines = 1, overflow = TextOverflow.Ellipsis)
}

// --- A thread ------------------------------------------------------------------------------

@Composable
// safeDrawingPadding includes the keyboard: the reply box sits right on top of it.
private fun ThreadScreen(id: String, social: Social, nav: Nav, startReply: Boolean = false) = Column(Modifier.fillMaxSize().safeDrawingPadding()) {
    TopBar("Thread", nav)
    val people by People.known.collectAsState()
    val liked by social.liked.collectAsState()
    // At once, from what's here already (the note you tapped, the thread if you've opened it before);
    // the note it answers and the replies come in around it, with a small spinner while they do.
    var thread by remember(id) { mutableStateOf(social.threadNow(id)) }
    var loading by remember(id) { mutableStateOf(true) }
    LaunchedEffect(id) {
        val full = social.thread(id)
        if (full.isNotEmpty() || thread == null) thread = full
        loading = false
    }
    // Who you're answering: the post you opened, or any other you tap Reply on.
    var target by remember(id) { mutableStateOf(id) }
    val focus = remember { FocusRequester() }
    var focusNow by remember(id) { mutableStateOf(startReply) }
    val shown = thread
    Box(Modifier.weight(1f)) {
        when {
            shown == null -> Box(Modifier.fillMaxWidth().padding(40.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Vault.Teal) }
            shown.isEmpty() -> Text("Couldn't find this post.", color = Vault.Muted, modifier = Modifier.padding(20.dp))
            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 12.dp)) {
                items(shown, key = { it.first.id }) { (e, depth) ->
                    NoteCard(e, people, e.id in liked, nav, onLike = { social.like(e) }, indent = minOf(depth, 4), lit = e.id == id && shown.size > 1 && depth > 0,
                        onReply = { target = e.id; focusNow = true })
                    if (depth == 0) HorizontalDivider(color = Vault.Edge)
                }
                if (loading) item(key = "loading") {
                    Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(Modifier.size(20.dp), color = Vault.Teal, strokeWidth = 2.dp) }
                }
            }
        }
    }
    val parent = shown?.firstOrNull { it.first.id == target }?.first ?: social.note(target)
    if (parent != null && social.me != null) {
        ReplyBox(parent, people, social, focus, onSent = { thread = social.threadNow(id) ?: thread }, onClear = if (target != id) ({ target = id }) else null)
        LaunchedEffect(focusNow, target) { if (focusNow) { focus.requestFocus(); focusNow = false } }
    }
}

/** Write a reply: to the post you opened, or the one you tapped Reply on. */
@Composable
private fun ReplyBox(parent: Event, people: Map<String, Person>, social: Social, focus: FocusRequester, onSent: () -> Unit, onClear: (() -> Unit)?) {
    var text by remember(parent.id) { mutableStateOf("") }
    var sending by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val name = people[parent.pubkey]?.shown ?: shortNpub(parent.pubkey)
    HorizontalDivider(color = Vault.Edge)
    Column(Modifier.fillMaxWidth().background(Vault.Ground).padding(start = 12.dp, end = 8.dp, top = 6.dp, bottom = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Replying to $name", color = Vault.Muted, style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false).padding(start = 4.dp))
            onClear?.let { Icon(Icons.Filled.Close, "Reply to the first post instead", tint = Vault.Muted, modifier = Modifier.padding(start = 4.dp).size(24.dp).clip(CircleShape).clickable(onClick = it).padding(4.dp)) }
        }
        Row(verticalAlignment = Alignment.Bottom) {
            TextField(text, { text = it }, Modifier.weight(1f).focusRequester(focus).heightIn(max = 160.dp), enabled = !sending,
                placeholder = { Text("Write a reply", color = Vault.Muted) },
                shape = RoundedCornerShape(20.dp),
                colors = TextFieldDefaults.colors(focusedContainerColor = Vault.Surface, unfocusedContainerColor = Vault.Surface, disabledContainerColor = Vault.Surface,
                    focusedIndicatorColor = Color.Transparent, unfocusedIndicatorColor = Color.Transparent, disabledIndicatorColor = Color.Transparent,
                    focusedTextColor = Vault.Text, unfocusedTextColor = Vault.Text, disabledTextColor = Vault.Muted, cursorColor = Vault.Teal))
            Spacer(Modifier.width(6.dp))
            val ready = text.isNotBlank() && !sending
            Box(Modifier.padding(bottom = 4.dp).size(48.dp).clip(CircleShape).background(if (ready) Vault.Teal else Vault.Surface).clickable(enabled = ready) {
                sending = true
                scope.launch {
                    if (social.reply(parent, text) != null) { text = ""; onSent() }
                    sending = false
                }
            }, contentAlignment = Alignment.Center) {
                if (sending) CircularProgressIndicator(Modifier.size(20.dp), color = Vault.Text, strokeWidth = 2.dp)
                else Icon(Icons.AutoMirrored.Filled.Send, "Send", tint = if (ready) Vault.Ground else Vault.Muted, modifier = Modifier.size(22.dp))
            }
        }
    }
}

// --- A profile -----------------------------------------------------------------------------

@Composable
private fun ProfileScreen(pk: String, social: Social, nav: Nav) = Column(Modifier.fillMaxSize().safeDrawingPadding()) {
    val people by People.known.collectAsState()
    val liked by social.liked.collectAsState()
    val follows by social.follows.collectAsState()
    val busy by social.busy.collectAsState()
    val p = people[pk]
    LaunchedEffect(pk) { People.want(listOf(pk)) }
    TopBar(p?.shown ?: "Profile", nav)
    // Their posts, a page at a time: more as you reach the end.
    var notes by remember(pk) { mutableStateOf<List<Event>?>(null) }
    var more by remember(pk) { mutableStateOf(true) }
    var paging by remember(pk) { mutableStateOf(false) }
    LaunchedEffect(pk) { notes = social.notesBy(pk) }
    val scope = rememberCoroutineScope()
    val nextPage = {
        val have = notes
        if (have != null && have.isNotEmpty() && more && !paging) {
            paging = true
            scope.launch {
                val next = social.notesBy(pk, until = have.minOf { it.createdAt }).filter { n -> have.none { it.id == n.id } }
                if (next.isEmpty()) more = false else notes = have + next
                paging = false
            }
        }
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
        item(key = "head") {
            Column(Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Avatar(p, pk, 72, Modifier.clickable(enabled = p?.picture != null) { p?.picture?.let { nav.pictures(listOf(it), 0) } })
                    Spacer(Modifier.width(16.dp))
                    Column(Modifier.weight(1f)) {
                        Text(p?.shown ?: shortNpub(pk), style = MaterialTheme.typography.titleLarge, color = Vault.Text)
                        p?.nip05?.let { Text(it.removePrefix("_@"), color = Vault.Muted, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    }
                }
                Spacer(Modifier.height(10.dp))
                val context = LocalContext.current
                Text(shortNpub(pk), fontFamily = PlexMono, color = Vault.Muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.clickable {
                    context.getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(android.content.ClipData.newPlainText("Account ID", cc.aaro.cosign.core.Nip19.npub(pk)))
                    social.message.value = "Copied their account ID"
                })
                p?.about?.let { Spacer(Modifier.height(10.dp)); Text(it, color = Vault.Text, style = MaterialTheme.typography.bodyMedium) }
                Spacer(Modifier.height(14.dp))
                when {
                    pk == social.me -> Text("This is you", color = Vault.Muted)
                    pk in busy || follows == null -> OutlinedButton({}, Modifier.height(44.dp), enabled = false, border = BorderStroke(1.dp, Vault.Line)) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = Vault.Teal, strokeWidth = 2.dp)
                    }
                    pk in follows!! -> OutlinedButton({ social.follow(pk, false) }, Modifier.height(44.dp), border = BorderStroke(1.dp, Vault.Line)) { Text("Following · Unfollow", color = Vault.Text) }
                    else -> Button({ social.follow(pk, true) }, Modifier.height(44.dp), colors = ButtonDefaults.buttonColors(Vault.Teal, Vault.Ground)) { Text("Follow") }
                }
                Spacer(Modifier.height(8.dp))
            }
            HorizontalDivider(color = Vault.Edge)
        }
        when {
            notes == null -> item(key = "loading") { Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Vault.Teal) } }
            notes!!.isEmpty() -> item(key = "none") { Text("No posts yet.", color = Vault.Muted, modifier = Modifier.padding(20.dp)) }
            else -> {
                items(notes!!, key = { it.id }) { n ->
                    NoteCard(n, people, n.id in liked, nav, onLike = { social.like(n) }, maxLines = 12)
                    HorizontalDivider(color = Vault.Edge)
                }
                item(key = "more") {
                    LaunchedEffect(notes!!.size) { nextPage() }
                    if (paging) Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(Modifier.size(20.dp), color = Vault.Teal, strokeWidth = 2.dp) }
                }
            }
        }
    }
}

// --- Search ----------------------------------------------------------------------------------

@Composable
private fun SearchScreen(social: Social, nav: Nav) = Column(Modifier.fillMaxSize().safeDrawingPadding()) {
    val found by social.found.collectAsState()
    val people by People.known.collectAsState()
    val liked by social.liked.collectAsState()
    var q by remember { mutableStateOf(found?.query ?: "") }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { if (found == null) focus.requestFocus() }
    val scope = rememberCoroutineScope()
    // A pasted link to someone or a post opens it; name@domain opens whoever it names.
    val open: (Ref) -> Unit = { r -> when (r) { is Ref.Profile -> nav.profile(r.pubkey); is Ref.Note -> nav.thread(r.id) } }
    val go = {
        val t = q.trim()
        Ref.parse(t)?.let(open) ?: run {
            social.search(t)
            if (Nip05.isAddress(t)) scope.launch { Nip05.lookup(t)?.takeIf { it.length == 64 }?.let { nav.profile(it) } }
        }
    }
    // As you type: a pasted link at once, words once you pause.
    LaunchedEffect(q) {
        val t = q.trim()
        if (t.isEmpty()) { social.clearSearch(); return@LaunchedEffect }
        Ref.parse(t)?.let { open(it); return@LaunchedEffect }
        if (t.length < 2) return@LaunchedEffect
        delay(350)
        social.search(t)
    }
    Row(Modifier.fillMaxWidth().padding(start = 4.dp, end = 12.dp, top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        IconButton(nav.back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Vault.Text) }
        TextField(
            q, { q = it }, Modifier.weight(1f).focusRequester(focus), singleLine = true,
            placeholder = { Text("People, posts, #tags…", color = Vault.Muted) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search), keyboardActions = KeyboardActions(onSearch = { go() }),
            trailingIcon = { if (q.isNotEmpty()) IconButton({ q = ""; social.clearSearch(); focus.requestFocus() }) { Icon(Icons.Filled.Close, "Clear", tint = Vault.Muted) } },
            shape = RoundedCornerShape(26.dp),
            colors = TextFieldDefaults.colors(focusedContainerColor = Vault.Surface, unfocusedContainerColor = Vault.Surface, focusedIndicatorColor = Color.Transparent,
                unfocusedIndicatorColor = Color.Transparent, focusedTextColor = Vault.Text, unfocusedTextColor = Vault.Text, cursorColor = Vault.Teal),
        )
    }
    val f = found ?: return@Column Text("Search names, words or #hashtags. Paste a link to someone or a post to open it.",
        color = Vault.Muted, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(20.dp))
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
        // Still looking: a spinner while there's nothing yet, a thin bar once results are showing.
        if (f.loading) item(key = "loading") {
            if (f.people.isEmpty() && f.notes.isEmpty()) Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Vault.Teal) }
            else androidx.compose.material3.LinearProgressIndicator(Modifier.fillMaxWidth().height(2.dp), color = Vault.Teal, trackColor = Color.Transparent)
        }
        if (f.people.isNotEmpty()) {
            item(key = "ph") { Heading("People") }
            items(f.people.take(10), key = { "p" + it }) { pk ->
                val p = people[pk]
                val h = f.hits[pk]
                Row(Modifier.fillMaxWidth().clickable { nav.profile(pk) }.padding(horizontal = 20.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(p, pk, 40)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(p?.shown ?: h?.name ?: shortNpub(pk), color = Vault.Text, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false))
                            if (h?.nip05 == Nip05.Check.OK) Icon(Icons.Filled.CheckCircle, "Checked", tint = Vault.Teal, modifier = Modifier.padding(start = 5.dp).size(15.dp))
                            if (h?.follow == true) Text("Following", color = Vault.Teal, style = MaterialTheme.typography.labelSmall,
                                modifier = Modifier.padding(start = 6.dp).border(1.dp, Vault.TealEdge, RoundedCornerShape(6.dp)).padding(horizontal = 5.dp, vertical = 1.dp))
                        }
                        // Their address (unless it named someone else), and how many follow them.
                        val line = listOfNotNull(p?.nip05?.removePrefix("_@")?.takeIf { h?.nip05 != Nip05.Check.WRONG && !it.startsWith("npub1") }, h?.followers?.takeIf { it > 0 }?.let { followers(it) })
                            .joinToString(" · ").ifEmpty { p?.about?.lineSequence()?.firstOrNull() ?: "" }
                        if (line.isNotEmpty()) Text(line, color = Vault.Muted, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        }
        if (f.notes.isNotEmpty()) {
            item(key = "nh") { Heading("Posts") }
            items(f.notes, key = { it.id }) { n ->
                NoteCard(n, people, n.id in liked, nav, onLike = { social.like(n) }, maxLines = 12)
                HorizontalDivider(color = Vault.Edge)
            }
        }
        if (!f.loading && f.people.isEmpty() && f.notes.isEmpty()) item(key = "none") { Text("Nothing found for “${f.query}”.", color = Vault.Muted, modifier = Modifier.padding(20.dp)) }
    }
}

private fun followers(n: Long) = when {
    n >= 1_000_000 -> "%.1fM followers".format(n / 1e6).replace(".0M", "M")
    n >= 10_000 -> "${n / 1000}K followers"
    n >= 1_000 -> "%.1fK followers".format(n / 1e3).replace(".0K", "K")
    n == 1L -> "1 follower"
    else -> "$n followers"
}

@Composable private fun Heading(text: String) = Text(text, style = MaterialTheme.typography.titleSmall, color = Vault.Muted, modifier = Modifier.padding(start = 20.dp, top = 16.dp, bottom = 4.dp))

// --- The bell ----------------------------------------------------------------------------------

@Composable
private fun BellScreen(phone: Phone, ui: Ui, social: Social, nav: Nav) = Column(Modifier.fillMaxSize().safeDrawingPadding()) {
    TopBar("Notifications", nav)
    val notices by social.notices.collectAsState()
    val people by People.known.collectAsState()
    // What was new when you opened this stays marked while you look.
    val seenBefore = remember { social.seenAt.value }
    LaunchedEffect(Unit) { social.loadNotices(force = true) }
    LaunchedEffect(notices.at) { if (notices.at != 0L) social.markSeen() }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    if (ui.asks.isNotEmpty() || ui.batchAsks.isNotEmpty() || ui.deleting.isNotEmpty()) LaunchedEffect(Unit) { while (true) { delay(1000); now = System.currentTimeMillis() } }
    val cards = needs(phone, ui)
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
        if (cards.isNotEmpty()) {
            item(key = "ch") { Heading("For your key") }
            items(cards) { c -> Box(Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) { NeedCard(c, phone, now) } }
        }
        item(key = "nh") { Heading("Replies, mentions and likes") }
        if (notices.list.isEmpty()) item(key = "empty") {
            if (notices.loading) Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Vault.Teal) }
            else Text("Nothing yet. When someone replies to you, mentions you or likes your notes, it shows up here.", color = Vault.Muted,
                style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp))
        }
        items(notices.list, key = { it.event.id }) { n -> NoticeRow(n, people, n.event.createdAt > seenBefore, social, nav) }
    }
}

@Composable
private fun NoticeRow(n: Notice, people: Map<String, Person>, fresh: Boolean, social: Social, nav: Nav) {
    val who = people[n.event.pubkey]
    val what = when (n.type) {
        Notice.Type.REPLY -> "replied"
        Notice.Type.MENTION -> "mentioned you"
        Notice.Type.REPOST -> "reposted your note"
        Notice.Type.REACTION -> n.event.content.let { if (it == "+" || it.isEmpty()) "liked your note" else if (it.startsWith(":")) "reacted to your note" else "reacted $it" }
    }
    val text = when (n.type) {
        Notice.Type.REPLY, Notice.Type.MENTION -> n.event.content
        else -> n.about?.let { social.note(it)?.content } ?: ""
    }
    Row(
        Modifier.fillMaxWidth().background(if (fresh) Vault.TealGround else Color.Transparent)
            .clickable { n.about?.let(nav::thread) }.padding(horizontal = 20.dp, vertical = 12.dp),
    ) {
        Avatar(who, n.event.pubkey, 36, Modifier.clickable { nav.profile(n.event.pubkey) })
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row {
                Text(who?.shown ?: shortNpub(n.event.pubkey), color = Vault.Text, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                Text(" $what · ${since(n.event.createdAt)}", color = Vault.Muted, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
            }
            if (text.isNotBlank()) Text(text, color = if (n.type == Notice.Type.REPLY || n.type == Notice.Type.MENTION) Vault.Text else Vault.Muted,
                style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
        }
    }
}
