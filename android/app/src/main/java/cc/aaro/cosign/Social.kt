package cc.aaro.cosign

import android.content.Context
import cc.aaro.cosign.core.Bech32
import cc.aaro.cosign.core.Clock
import cc.aaro.cosign.core.Event
import cc.aaro.cosign.core.Json
import cc.aaro.cosign.core.Nip19
import cc.aaro.cosign.core.isHex32
import cc.aaro.cosign.core.toHex
import cc.aaro.cosign.net.Fetch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.ConcurrentHashMap

// The home screen's Nostr: a Discover feed, search, threads, your notifications, and
// the two things you can do here (like a note, follow someone). Read once when asked,
// never kept subscribed. Your likes and follows sign through your servers like an app's.

/** The app's name, from its one string resource: renaming the app is a one-line change there. */
val appName: String get() = CosignApp.instance.getString(R.string.app_name)

/** Where things are read from. Lists, so one relay being down never empties a screen. */
object Sources {
    /** Discover, best first: the first that has notes is the feed. discover.syb.lol runs on one home machine. */
    val FEEDS = listOf(
        "wss://discover.syb.lol",
        "wss://feeds.nostrarchives.com/notes/trending/reactions/today",
        "wss://trending.relays.land",
    )
    /** NIP-50 search, all asked at once (relay.nostr.band and relay.noswhere.com didn't answer when this was written). */
    val SEARCH = listOf("wss://search.nos.today", "wss://search.nostrarchives.com", "wss://relay.ditto.pub")
    val PROFILES = listOf("wss://purplepag.es", "wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net", "wss://indexer.coracle.social")
    val GENERAL = listOf("wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net")
    /** Debug builds only: more relays to read from (a local relay for tests). */
    val extra = MutableStateFlow<List<String>>(emptyList())
    /** Debug builds only: publish your own likes, follows and mutes to [extra] alone, nowhere public. */
    @Volatile var localOnly = false
}

/** Someone's kind 0, as shown. */
data class Person(val pubkey: String, val name: String?, val picture: String?, val about: String?, val nip05: String?, val at: Long) {
    val npub get() = Nip19.npub(pubkey)
    val shown get() = name?.takeIf { it.isNotBlank() } ?: shortNpub(pubkey)

    companion object {
        fun of(e: Event): Person? {
            val m = try { Json.parse(e.content) as? Map<*, *> } catch (_: Exception) { null } ?: return null
            fun s(k: String) = (m[k] as? String)?.trim()?.takeIf { it.isNotEmpty() }
            return Person(e.pubkey, (s("display_name") ?: s("displayName") ?: s("name"))?.take(60), s("picture")?.takeIf { it.startsWith("https://") },
                s("about")?.take(400), s("nip05"), e.createdAt)
        }
    }
}

fun shortNpub(pk: String) = try { Nip19.npub(pk).let { it.take(10) + "…" + it.takeLast(4) } } catch (_: Exception) { pk.take(8) }

/**
 * Profiles, for every key on this phone: in memory, and the most recent few hundred on disk
 * so the feed has names and pictures the moment it opens. Asked for in batches.
 */
object People {
    val known = MutableStateFlow<Map<String, Person>>(emptyMap())
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val asked = ConcurrentHashMap<String, Long>()
    private val pending = LinkedHashSet<String>()
    private var batch: Job? = null
    private var file: File? = null
    private var saving: Job? = null

    fun init(context: Context) {
        if (file != null) return
        file = File(context.cacheDir, "people.json")
        scope.launch {
            val list = try { (Json.parse(file!!.readText()) as? List<*>)?.mapNotNull { Event.fromMap(it)?.let(Person::of) } } catch (_: Exception) { null } ?: return@launch
            known.update { have -> list.associateBy { it.pubkey } + have }
        }
    }

    /** Fetch these profiles, unless asked for in the last ten minutes. */
    fun want(pubkeys: Collection<String>) {
        val now = System.currentTimeMillis()
        synchronized(pending) {
            for (pk in pubkeys) if (isHex32(pk) && now - (asked[pk] ?: 0) > 600_000) { asked[pk] = now; pending += pk }
            if (pending.isEmpty() || batch?.isActive == true) return
            batch = scope.launch {
                delay(250)
                val take = synchronized(pending) { pending.toList().also { pending.clear() } }
                take.chunked(100).map { part -> async { Fetch.query(Sources.PROFILES + Sources.extra.value, mapOf("kinds" to listOf(0), "authors" to part), 6000) } }
                    .awaitAll().flatten().let(::add)
                synchronized(pending) { if (pending.isNotEmpty()) want(emptyList()) }
            }
        }
    }

    /** Kind 0s from anywhere (a search, say): keep the newest of each. */
    fun add(events: List<Event>) {
        val fresh = events.filter { it.kind == 0 }.groupBy { it.pubkey }.mapNotNull { (_, es) -> es.maxBy { it.createdAt }.let { e -> Person.of(e)?.let { e to it } } }
        if (fresh.isEmpty()) return
        known.update { have -> have + fresh.filter { (_, p) -> (have[p.pubkey]?.at ?: -1) < p.at }.associate { (_, p) -> p.pubkey to p } }
        raw.putAll(fresh.associate { (e, p) -> p.pubkey to e })
        save()
    }

    private val raw = ConcurrentHashMap<String, Event>()

    private fun save() {
        if (saving?.isActive == true) return
        saving = scope.launch {
            delay(3000)
            val f = file ?: return@launch
            // Keep the newest few hundred: what was seen last is what's likely to be seen again.
            val old = try { (Json.parse(f.readText()) as? List<*>)?.mapNotNull { Event.fromMap(it) } } catch (_: Exception) { null } ?: emptyList()
            val all = (old.associateBy { it.pubkey } + raw).values.sortedByDescending { it.createdAt }.take(600)
            try { f.writeText(Json.stringify(all.map { it.toMap() })) } catch (_: Exception) {}
        }
    }
}

/** A Nostr identifier typed or pasted into search. */
sealed class Ref {
    data class Profile(val pubkey: String) : Ref()
    data class Note(val id: String) : Ref()

    companion object {
        fun parse(input: String): Ref? {
            val s = input.trim().removePrefix("nostr:").removePrefix("@")
            if (isHex32(s.lowercase())) return Profile(s.lowercase())
            val (hrp, data) = try { Bech32.decode(s, 2000) } catch (_: Exception) { return null }
            return when (hrp) {
                "npub" -> if (data.size == 32) Profile(data.toHex()) else null
                "note" -> if (data.size == 32) Note(data.toHex()) else null
                "nprofile" -> tlv(data)?.let { Profile(it) }
                "nevent" -> tlv(data)?.let { Note(it) }
                else -> null
            }
        }

        /** The 32 bytes under type 0 of a NIP-19 TLV. */
        private fun tlv(b: ByteArray): String? {
            var i = 0
            while (i + 2 <= b.size) {
                val t = b[i].toInt() and 0xff; val l = b[i + 1].toInt() and 0xff
                if (i + 2 + l > b.size) return null
                if (t == 0 && l == 32) return b.copyOfRange(i + 2, i + 34).toHex()
                i += 2 + l
            }
            return null
        }
    }
}

/** What a note replies to: the note right above it, and the thread's first note. */
fun parentOf(e: Event): String? {
    val es = e.tags.filter { it.size > 1 && it[0] == "e" }
    return es.firstOrNull { it.getOrNull(3) == "reply" }?.get(1) ?: es.firstOrNull { it.getOrNull(3) == "root" }?.get(1)
        ?: es.lastOrNull { it.getOrNull(3).isNullOrEmpty() || it[3] !in setOf("mention") }?.get(1)
}
fun rootOf(e: Event): String? {
    val es = e.tags.filter { it.size > 1 && it[0] == "e" }
    return es.firstOrNull { it.getOrNull(3) == "root" }?.get(1) ?: es.firstOrNull { it.getOrNull(3).isNullOrEmpty() }?.get(1)
}

data class Feed(val notes: List<Event> = emptyList(), val loading: Boolean = false, val source: String? = null, val failed: Boolean = false, val at: Long = 0, val more: Boolean = true)

data class Notice(val event: Event, val type: Type, val about: String?) {
    enum class Type { REPLY, MENTION, REACTION, REPOST }
}

data class Notices(val list: List<Notice> = emptyList(), val loading: Boolean = false, val at: Long = 0)

data class Found(val query: String, val people: List<String> = emptyList(), val notes: List<Event> = emptyList(), val loading: Boolean = true)

/** One of your actions in Cosign that your servers want you to approve first. */
data class Held(val what: String, val event: Event)

/** The home screen's state for one key. */
class Social private constructor(private val phone: Phone, context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val prefs = context.getSharedPreferences("social." + (phone.ui.value.member?.group?.groupX?.take(16) ?: phone.slot), Context.MODE_PRIVATE)
    val me get() = phone.ui.value.member?.group?.groupX

    val feed = MutableStateFlow(Feed())
    val notices = MutableStateFlow(Notices())
    /** Notifications newer than this were not seen yet: the bell's dot. */
    val seenAt = MutableStateFlow(prefs.getLong("seen", 0))
    val liked = MutableStateFlow(prefs.getStringSet("liked", emptySet())!!.toSet())
    /** Who you follow, from your newest follow list. Null until it's known. */
    val follows = MutableStateFlow<Set<String>?>(null)
    /** People being followed or unfollowed right now. */
    val busy = MutableStateFlow<Set<String>>(emptySet())
    /** Something to say briefly ("Couldn't like that: …"). */
    val message = MutableStateFlow<String?>(null)
    val held = MutableStateFlow<Held?>(null)

    private var contacts: Event? = null

    private fun readRelays(): List<String> {
        val mine = phone.latest("10002")?.tags?.filter { it.size > 1 && it[0] == "r" && it.getOrNull(2) != "write" }?.map { it[1] } ?: emptyList()
        return (mine.take(4) + Sources.GENERAL + Sources.extra.value).distinct()
    }
    private fun writeRelays(): List<String> {
        val mine = phone.latest("10002")?.tags?.filter { it.size > 1 && it[0] == "r" && it.getOrNull(2) != "read" }?.map { it[1] } ?: emptyList()
        val group = phone.ui.value.member?.group?.relays ?: emptyList()
        return (mine.take(4) + group + Sources.GENERAL + Sources.extra.value).distinct().take(9)
    }

    // --- Discover -----------------------------------------------------------------

    /** Load the feed: from the first source that has notes. [force]: even if it's fresh. */
    fun loadFeed(force: Boolean = false) {
        val f = feed.value
        if (f.loading || (!force && f.notes.isNotEmpty() && System.currentTimeMillis() - f.at < 30 * 60_000)) return
        feed.update { it.copy(loading = true, failed = false) }
        scope.launch { knowFollows(); knowMutes() }
        lookedAt = 0
        loadPlaces()
        scope.launch {
            // The curated feed first. If it has less than a screenful or two, the next source tops it up
            // (after it, never mixed in). A bit more is asked for than is shown, as some is left out.
            var used: String? = null
            val fresh = ArrayList<Event>()
            for (src in Sources.FEEDS) {
                Startup.mark("feed asked")
                val got = Fetch.query(listOf(src), mapOf("kinds" to listOf(1), "limit" to 60), 8000)
                Startup.mark("feed fetched ${got.size}")
                val notes = got.filter { it.kind == 1 && forDiscover(it) && fresh.none { f -> f.id == it.id } }
                Startup.mark("feed filtered ${notes.size}")
                if (notes.isEmpty()) continue
                if (used == null) used = src
                fresh += rank(notes)
                if (fresh.size >= 20) break
            }
            if (fresh.size < 3) return@launch feed.update { it.copy(loading = false, failed = it.notes.isEmpty()) }
            remember(fresh)
            People.want(fresh.map { it.pubkey })
            // What's on screen stays where it is; the new notes come after it. A refresh you asked for starts over.
            feed.update { cur ->
                val keep = if (force || cur.notes.isEmpty()) emptyList() else cur.notes.take(lookedAt + 3)
                Feed(keep + fresh.filter { n -> keep.none { it.id == n.id } }, source = used, at = System.currentTimeMillis())
            }
            saveFeed()
        }
    }

    // The last feed, on disk, so opening shows it at once (filtered again: you may have muted someone since).
    private val feedFile = File(context.cacheDir, "feed-" + (phone.ui.value.member?.group?.groupX?.take(16) ?: phone.slot) + ".json")

    /** Called once the whole object is set up: the filters below need it. */
    private fun restoreFeed() {
        scope.launch {
            val m = try { Json.parse(feedFile.readText()) as? Map<*, *> } catch (_: Exception) { null } ?: return@launch
            val notes = (m["notes"] as? List<*>)?.mapNotNull { Event.fromMap(it) }?.filter { forDiscover(it) } ?: return@launch
            if (notes.isEmpty()) return@launch
            remember(notes)
            People.want(notes.map { it.pubkey })
            feed.update { if (it.notes.isNotEmpty()) it else it.copy(notes = notes, source = m["source"] as? String, at = m["at"] as? Long ?: 0) }
            Startup.mark("feed from cache ${notes.size}")
        }
    }

    private fun saveFeed() {
        val f = feed.value
        try { feedFile.writeText(Json.stringify(mapOf("source" to f.source, "at" to f.at, "notes" to f.notes.take(40).map { it.toMap() }))) } catch (_: Exception) {}
    }

    /** Older notes from the same source. */
    fun loadMore() {
        val f = feed.value
        val src = f.source ?: return
        if (f.loading || !f.more || f.notes.isEmpty()) return
        feed.update { it.copy(loading = true) }
        scope.launch {
            val until = f.notes.minOf { it.createdAt } - 1
            val got = Fetch.query(listOf(src), mapOf("kinds" to listOf(1), "limit" to 60, "until" to until), 8000)
            val more = got.filter { it.kind == 1 && forDiscover(it) && f.notes.none { n -> n.id == it.id } }
            remember(more)
            People.want(more.map { it.pubkey })
            feed.update { it.copy(notes = it.notes + more.sortedByDescending { n -> n.createdAt }, loading = false, more = got.isNotEmpty()) }
        }
    }

    /** Newest first; replies only when the feed has little else. */
    private fun rank(notes: List<Event>): List<Event> {
        val (top, replies) = notes.sortedByDescending { it.createdAt }.partition { parentOf(it) == null }
        return if (top.size >= 15) top else top + replies
    }

    // --- Places: a few videos from sites you're signed in to, mixed into Discover ---------

    /** The cards, and the note they go before (-1: not placed). Placed once, never moved. */
    data class Videos(val cards: List<PlaceCard> = emptyList(), val start: Int = -1)
    val videos = MutableStateFlow(Videos())
    /** How far down Discover you've looked, in notes: cards that come late go below it. */
    @Volatile var lookedAt = 0
    private val tube by lazy { TubeFeed(CosignApp.instance, phone.slot + "." + (me?.take(16) ?: ""), { me }, { phone.signOwn(it) }) }
    private val places: List<PlaceFeed> get() = if (Places.fake) listOf(FakeTube()) else listOf(tube)

    private fun loadPlaces() {
        val opened = System.currentTimeMillis()
        // Last time's cards show at once; this time's are kept for next time unless they're on time.
        val cached = cachedCards()
        videos.value = if (cached.isEmpty()) Videos() else Videos(cached, 1)
        scope.launch {
            val got = kotlinx.coroutines.withTimeoutOrNull(8000) {
                places.map { p -> async { try { p.fetch() } catch (_: Exception) { emptyList() } } }.awaitAll()
            } ?: return@launch
            // Every place turned this account away, or has nothing: no cards at all.
            val cards = got.filterNotNull().flatten()
            if (got.all { it == null } || cards.isEmpty()) { prefs.edit().remove("places").apply(); videos.value = Videos(); return@launch }
            prefs.edit().putString("places", Json.stringify(cards.map { mapOf("id" to it.id, "title" to it.title, "channel" to it.channel, "thumb" to it.thumb,
                "url" to it.url, "duration" to it.duration, "published" to it.published, "label" to it.label) })).apply()
            if (videos.value.cards.isNotEmpty()) return@launch // never reshuffle what's on screen
            val late = System.currentTimeMillis() - opened
            val start = when {
                // Within the budget, or before Discover had anything to show: near the top.
                late <= 1500 || feed.value.notes.isEmpty() -> 1
                // A little late: below what you've looked at.
                else -> lookedAt + 4
            }
            videos.value = Videos(cards, start)
        }
    }

    private fun cachedCards(): List<PlaceCard> = try {
        (Json.parse(prefs.getString("places", null) ?: "[]") as List<*>).mapNotNull { x ->
            val m = x as? Map<*, *> ?: return@mapNotNull null
            PlaceCard(m["id"] as String, m["title"] as String, m["channel"] as String, m["thumb"] as? String, m["url"] as String,
                (m["duration"] as? Long)?.toInt(), m["published"] as? Long, m["label"] as? String ?: "")
        }
    } catch (_: Exception) { emptyList() }

    // --- Search ---------------------------------------------------------------------

    val found = MutableStateFlow<Found?>(null)
    private var searching: Job? = null

    fun search(q: String) {
        val text = q.trim()
        if (text.isEmpty()) return
        searching?.cancel()
        found.value = Found(text)
        searching = scope.launch {
            val tag = text.removePrefix("#").takeIf { text.startsWith("#") && it.isNotBlank() && !it.contains(' ') }?.lowercase()
            val search = Sources.SEARCH + Sources.extra.value
            val people = async {
                if (tag != null) emptyList() else {
                    val byNip05 = nip05(text)
                    val events = Fetch.query(search, mapOf("kinds" to listOf(0), "search" to text, "limit" to 20), 7000)
                    People.add(events)
                    (listOfNotNull(byNip05) + events.sortedByDescending { matchScore(it, text) }.map { it.pubkey }).distinct().take(20)
                }
            }
            val notes = async {
                val filter: Map<String, Any> = if (tag != null) mapOf("kinds" to listOf(1), "#t" to listOf(tag), "limit" to 40)
                    else mapOf("kinds" to listOf(1), "search" to text, "limit" to 40)
                val relays = if (tag != null) search + Sources.GENERAL else search
                Fetch.query(relays, filter, 8000).filter { it.kind == 1 && safe(it) }.sortedByDescending { it.createdAt }.take(60)
            }
            val p = people.await()
            val n = notes.await()
            remember(n)
            People.want(p + n.map { it.pubkey })
            found.value = Found(text, p, n, loading = false)
        }
    }

    fun clearSearch() { searching?.cancel(); found.value = null }

    private fun matchScore(e: Event, q: String): Int {
        val p = Person.of(e) ?: return 0
        val name = p.name?.lowercase() ?: return 0
        val ql = q.lowercase()
        return when { name == ql -> 3; name.startsWith(ql) -> 2; ql in name -> 1; else -> 0 }
    }

    /** name@domain (or just a domain): its NIP-05 key, if it has one. */
    private fun nip05(q: String): String? {
        val m = Regex("^(?:([a-zA-Z0-9._-]+)@)?([a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)+)$").matchEntire(q) ?: return null
        val name = m.groupValues[1].ifEmpty { "_" }.lowercase()
        val url = "https://${m.groupValues[2].lowercase()}/.well-known/nostr.json?name=$name"
        return try {
            val call = Fetch.http.newBuilder().callTimeout(5, java.util.concurrent.TimeUnit.SECONDS).followRedirects(false).build()
                .newCall(okhttp3.Request.Builder().url(url).build())
            call.execute().use { r -> if (!r.isSuccessful) null else ((Json.parse(r.body!!.string()) as? Map<*, *>)?.get("names") as? Map<*, *>)?.get(name) as? String }
                ?.takeIf { isHex32(it) }
        } catch (_: Exception) { null }
    }

    // --- Threads and profiles --------------------------------------------------------

    /** The whole thread [id] is in: its first note, then the replies, each with how deep it sits. */
    suspend fun thread(id: String): List<Pair<Event, Int>> {
        val relays = readRelays() + listOfNotNull(feed.value.source) + Sources.SEARCH.take(1)
        val note = note(id) ?: Fetch.query(relays, mapOf("ids" to listOf(id)), 6000).firstOrNull()?.also { remember(listOf(it)) } ?: return emptyList()
        val rootId = rootOf(note) ?: note.id
        val got = Fetch.query(relays, listOf(mapOf("ids" to listOf(rootId)), mapOf("kinds" to listOf(1), "#e" to listOf(rootId), "limit" to 200)), 7000)
        val root = if (rootId == note.id) note else note(rootId) ?: got.firstOrNull { it.id == rootId }
        // Replies, not notes that only mention it.
        val replies = got.filter { e -> e.kind == 1 && e.id != rootId && safe(e) && e.tags.any { it.size > 1 && it[0] == "e" && it[1] == rootId && it.getOrNull(3) != "mention" } }
        val all = listOfNotNull(root) + replies + (if (root == null) listOf(note) else emptyList())
        remember(all)
        People.want(all.map { it.pubkey })
        // Each reply under the note it answers, oldest first.
        val byParent = all.drop(1).distinctBy { it.id }.groupBy { parentOf(it)?.takeIf { p -> all.any { a -> a.id == p } } ?: all.first().id }
        val out = ArrayList<Pair<Event, Int>>()
        fun walk(e: Event, depth: Int) {
            if (out.any { it.first.id == e.id }) return
            out += e to depth
            byParent[e.id]?.sortedBy { it.createdAt }?.forEach { walk(it, depth + 1) }
        }
        walk(all.first(), 0)
        return out
    }

    suspend fun notesBy(pk: String): List<Event> {
        People.want(listOf(pk))
        val ns = Fetch.query(readRelays() + Sources.PROFILES.take(2), mapOf("kinds" to listOf(1), "authors" to listOf(pk), "limit" to 30), 7000)
        remember(ns)
        return ns.sortedByDescending { it.createdAt }
    }

    // --- Notifications ---------------------------------------------------------------

    fun loadNotices(force: Boolean = false) {
        val me = me ?: return
        val n = notices.value
        if (n.loading || (!force && n.at != 0L && System.currentTimeMillis() - n.at < 5 * 60_000)) return
        notices.update { it.copy(loading = true) }
        scope.launch {
            val evs = Fetch.query(readRelays(), mapOf("kinds" to listOf(1, 6, 7), "#p" to listOf(me), "limit" to 80), 7000).filter { it.pubkey != me && it.pubkey !in muted.value }
            val list = evs.sortedByDescending { it.createdAt }.map { e ->
                when (e.kind) {
                    7 -> Notice(e, Notice.Type.REACTION, e.tags.lastOrNull { it.size > 1 && it[0] == "e" }?.get(1))
                    6 -> Notice(e, Notice.Type.REPOST, e.tags.lastOrNull { it.size > 1 && it[0] == "e" }?.get(1))
                    else -> if (parentOf(e) != null) Notice(e, Notice.Type.REPLY, e.id) else Notice(e, Notice.Type.MENTION, e.id)
                }
            }
            remember(evs.filter { it.kind == 1 })
            // What the likes were on: your notes.
            val about = list.filter { it.type == Notice.Type.REACTION || it.type == Notice.Type.REPOST }.mapNotNull { it.about }.distinct().filter { note(it) == null }
            if (about.isNotEmpty()) remember(Fetch.query(readRelays(), mapOf("ids" to about.take(60)), 5000))
            People.want(list.map { it.event.pubkey })
            notices.value = Notices(list, at = System.currentTimeMillis())
        }
    }

    fun unseen(): Int = notices.value.list.count { it.event.createdAt > seenAt.value }

    fun markSeen() {
        val newest = notices.value.list.maxOfOrNull { it.event.createdAt } ?: return
        if (newest <= seenAt.value) return
        seenAt.value = newest
        prefs.edit().putLong("seen", newest).apply()
    }

    // --- Likes and follows -------------------------------------------------------------

    fun like(note: Event) {
        val me = me ?: return
        if (note.id in liked.value) return
        mark(note.id, true)
        scope.launch {
            val tags = listOf(listOf("e", note.id), listOf("p", note.pubkey), listOf("k", note.kind.toString()))
            if (!act(Event(me, Clock.now(), 7, tags, "+").withId())) mark(note.id, false)
        }
    }

    private fun mark(id: String, on: Boolean) {
        liked.update { if (on) it + id else it - id }
        prefs.edit().putStringSet("liked", liked.value.toList().takeLast(2000).toSet()).apply()
    }

    fun follow(pk: String, on: Boolean) {
        val me = me ?: return
        if (pk in busy.value || pk == me) return
        busy.update { it + pk }
        scope.launch {
            try {
                // Start from your newest follow list anywhere, never from an empty one by mistake.
                val list = newestContacts(fetch = true)
                if (list == null && !on) return@launch
                val old = list?.tags ?: emptyList()
                val has = old.any { it.size > 1 && it[0] == "p" && it[1] == pk }
                if (has == on) { contacts = list; follows.value = followsIn(list); return@launch }
                val tags = if (on) old + listOf(listOf("p", pk)) else old.filterNot { it.size > 1 && it[0] == "p" && it[1] == pk }
                val at = maxOf(Clock.now(), (list?.createdAt ?: 0) + 1)
                act(Event(me, at, 3, tags, list?.content ?: "").withId())
            } finally { busy.update { it - pk } }
        }
    }

    private fun followsIn(e: Event?) = e?.tags?.filter { it.size > 1 && it[0] == "p" }?.map { it[1] }?.toSet() ?: emptySet()

    /** Your newest follow list: what this phone has seen signed, or what your relays have. */
    private suspend fun newestContacts(fetch: Boolean): Event? = newest(3, contacts, fetch)

    /** Your newest version of a list (follows, mutes): what this phone has seen signed, or what your relays have. */
    private suspend fun newest(kind: Int, have: Event?, fetch: Boolean): Event? {
        val me = me ?: return null
        val local = listOfNotNull(phone.latest(kind.toString()), have)
        val remote = if (fetch) Fetch.query((writeRelays() + Sources.PROFILES).distinct(), mapOf("kinds" to listOf(kind), "authors" to listOf(me), "limit" to 1), 6000)
            .filter { it.pubkey == me && it.kind == kind } else emptyList()
        return (local + remote).maxByOrNull { it.createdAt }
    }

    // --- Keeping Discover pleasant ---------------------------------------------------------

    /** People you muted: your mute list's public part, and the ones muted here. */
    val muted = MutableStateFlow(prefs.getStringSet("muted", emptySet())!!.toSet())
    /** Notes you said you're not interested in. Only on this phone. */
    val dismissed = MutableStateFlow(prefs.getStringSet("dismissed", emptySet())!!.toSet())
    private val languages by lazy { Lang.phone() }
    private var mutes: Event? = null

    /** Shown anywhere: no content warning, nothing adult, nobody you muted. */
    fun safe(e: Event) = !Safety.flagged(e) && e.pubkey !in muted.value && e.id !in dismissed.value
    /** In Discover, also only in a language this phone is set to. */
    private fun forDiscover(e: Event) = safe(e) && !snoozedNow(e.pubkey) && Lang.readable(e, languages)

    /** People whose notes you said you're not interested in, until when (ms): Discover leaves them out for a while. */
    val snoozed = MutableStateFlow(prefs.getStringSet("snoozed", emptySet())!!.mapNotNull { s ->
        s.substringAfter(':').toLongOrNull()?.takeIf { it > System.currentTimeMillis() }?.let { s.substringBefore(':') to it } }.toMap())

    /** Not this note, and less like it: the same author is left out of Discover for three days. */
    fun notInterested(e: Event) {
        dismissed.update { it + e.id }
        snoozed.update { it + (e.pubkey to System.currentTimeMillis() + 3 * 86_400_000L) }
        prefs.edit().putStringSet("dismissed", dismissed.value.toList().takeLast(2000).toSet())
            .putStringSet("snoozed", snoozed.value.map { (pk, until) -> "$pk:$until" }.toSet()).apply()
    }

    fun snoozedNow(pk: String) = (snoozed.value[pk] ?: 0) > System.currentTimeMillis()

    /** Mute someone: hidden here at once, and added to your mute list (kind 10000), signed like a follow. */
    fun mute(pk: String) {
        val me = me ?: return
        if (pk == me) return
        muted.update { it + pk }
        prefs.edit().putStringSet("muted", muted.value).apply()
        scope.launch {
            val list = newest(10000, mutes, fetch = true)
            val old = list?.tags ?: emptyList()
            if (old.any { it.size > 1 && it[0] == "p" && it[1] == pk }) return@launch
            // The private part (encrypted in content) stays as it was.
            val ev = Event(me, maxOf(Clock.now(), (list?.createdAt ?: 0) + 1), 10000, old + listOf(listOf("p", pk)), list?.content ?: "").withId()
            act(ev)
        }
    }

    /** Your mute list, read from your relays once per run of the app; between runs, what was read is kept here. */
    @Volatile private var mutesKnown = false
    private suspend fun knowMutes() {
        if (mutesKnown) return
        val list = newest(10000, mutes, fetch = true) ?: return
        mutesKnown = true
        mutes = list
        val pks = list.tags.filter { it.size > 1 && it[0] == "p" }.map { it[1] }
        if (pks.isNotEmpty()) { muted.update { it + pks }; prefs.edit().putStringSet("muted", muted.value).apply() }
    }

    private suspend fun knowFollows() {
        if (follows.value != null) return
        val c = newestContacts(fetch = true)
        contacts = c
        follows.value = followsIn(c)
    }

    /** Your servers sign it (or hand it to you to approve), then it goes to your relays. */
    private suspend fun act(ev: Event, approved: Boolean = false): Boolean {
        val signed = try { phone.signOwn(ev, approved) } catch (e: NeedsApproval) {
            held.value = Held(e.what, ev); return false
        } catch (e: Exception) {
            message.value = "Couldn't do that right now: ${e.message ?: "no answer"}"; return false
        }
        if (signed.kind == 3) { contacts = signed; follows.value = followsIn(signed) }
        if (signed.kind == 10000) mutes = signed
        val n = Fetch.publish(if (Sources.localOnly) Sources.extra.value else writeRelays(), signed)
        if (n == 0) message.value = "Signed, but no relay took it. Try again later."
        return n > 0
    }

    /** You approved (or not) one of your own actions your servers held. */
    fun decideHeld(approve: Boolean) {
        val h = held.value ?: return
        held.value = null
        if (!approve) { if (h.event.kind == 7) h.event.firstTag("e")?.let { mark(it, false) }; return }
        scope.launch { act(h.event, approved = true) }
    }

    // --- Notes seen, by id ----------------------------------------------------------------

    fun note(id: String): Event? = noteOf(id)

    companion object {
        private val notes = object : LinkedHashMap<String, Event>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Event>?) = size > 1500
        }
        private fun remember(es: List<Event>) = synchronized(notes) { for (e in es) notes[e.id] = e }
        private fun noteOf(id: String) = synchronized(notes) { notes[id] }

        private val all = HashMap<String, Social>()
        fun of(phone: Phone): Social = synchronized(all) {
            all.getOrPut(phone.slot + "/" + phone.ui.value.member?.group?.groupX) { People.init(CosignApp.instance); Social(phone, CosignApp.instance).also { it.restoreFeed() } }
        }
    }

    private fun remember(es: List<Event>) = Companion.remember(es)
}
