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
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.joinAll
import java.io.File
import java.util.concurrent.ConcurrentHashMap

// The home screen's Nostr: a Discover feed, search, threads, your notifications, and
// the two things you can do here (like a note, follow someone). Read once when asked,
// never kept subscribed. Your likes and follows sign through your servers like an app's.

/** The app's name, from its one string resource: renaming the app is a one-line change there. */
val appName: String get() = CosignApp.instance.getString(R.string.app_name)

/** What Discover shows: notes, and NIP-71 video events (normal and short) when a feed carries them. */
val FEED_KINDS = listOf(1, 21, 22)

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

/** Someone with no name yet, shown by a piece of their account ID (without the "npub1" in front). */
fun shortNpub(pk: String) = try { Nip19.npub(pk).let { it.drop(5).take(6) + "…" + it.takeLast(4) } } catch (_: Exception) { pk.take(8) }

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
            // A web link that carries one (njump.me/npub1…, primal.net/e/nevent1…): the identifier inside it.
            val id = if (s.contains('/') || s.contains('?')) ENTITY.find(s.lowercase())?.value ?: return null else s
            val (hrp, data) = try { Bech32.decode(id, 2000) } catch (_: Exception) { return null }
            return when (hrp) {
                "npub" -> if (data.size == 32) Profile(data.toHex()) else null
                "note" -> if (data.size == 32) Note(data.toHex()) else null
                "nprofile" -> tlv(data)?.let { Profile(it) }
                "nevent" -> tlv(data)?.let { Note(it) }
                else -> null
            }
        }

        private val ENTITY = Regex("(npub1|nprofile1|note1|nevent1)[02-9ac-hj-np-z]+")

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

data class Found(val query: String, val people: List<String> = emptyList(), val notes: List<Event> = emptyList(), val loading: Boolean = true, val hits: Map<String, Hit> = emptyMap())

/** One of your actions in Cosign that your servers want you to approve first. */
data class Held(val what: String, val event: Event)

/** The home screen's state for one key. */
class Social private constructor(private val phone: Phone, context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val prefs = context.getSharedPreferences("social." + (phone.ui.value.member?.group?.groupX?.take(16) ?: phone.slot), Context.MODE_PRIVATE)
    val me get() = phone.ui.value.member?.group?.groupX

    val feed = MutableStateFlow(Feed())
    /** Done when the first Discover cards are on screen. Reads in the background wait for it (2.5 s at most), so they don't slow that first paint. */
    val painted = kotlinx.coroutines.CompletableDeferred<Unit>()
    private suspend fun afterPaint() { kotlinx.coroutines.withTimeoutOrNull(2500) { painted.await() } }
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
        if (f.loading || (!force && f.notes.isNotEmpty() && System.currentTimeMillis() - f.at < 30 * 60_000)) {
            // The notes are fresh enough; the videos may not be loaded yet.
            if (!f.loading && videos.value.cards.isEmpty()) loadPlaces()
            return
        }
        feed.update { it.copy(loading = true, failed = false) }
        scope.launch { afterPaint(); knowFollows(); knowMutes() }
        lookedAt = 0
        loadPlaces()
        scope.launch {
            // With last time's feed to show, that goes on screen first; without one, this is what's awaited.
            if (feed.value.notes.isNotEmpty() || feedFile.exists()) afterPaint()
            // The curated feed first. If it has less than a screenful or two, the next source tops it up
            // (after it, never mixed in). A bit more is asked for than is shown, as some is left out.
            var used: String? = null
            val fresh = ArrayList<Event>()
            val foreign = ArrayList<Event>()
            for (src in Sources.FEEDS) {
                Startup.mark("feed asked")
                val got = Fetch.query(listOf(src), mapOf("kinds" to FEED_KINDS, "limit" to 60), 8000)
                Startup.mark("feed fetched ${got.size}")
                // Roots with something in them, nothing heavy; then two per person and one "GM" a page.
                // The curated source keeps its own order (its ranking); the others go newest first.
                val ok = got.filter { it.kind in FEED_KINDS && Curate.keep(it) && forDiscover(it) && fresh.none { f -> f.id == it.id } }
                val notes = Curate.page(if (src == Sources.FEEDS[0]) ok else ok.sortedByDescending { it.createdAt }, already = fresh)
                Startup.mark("feed filtered ${notes.size}")
                foreign += got.filter { it.kind in FEED_KINDS && Curate.keep(it) && foreignOk(it) && foreign.none { f -> f.id == it.id } }
                if (notes.isEmpty()) continue
                if (used == null) used = src
                fresh += notes
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
            translateIn(foreign)
        }
    }

    // The last feed, on disk, so opening shows it at once (filtered again: you may have muted someone since).
    private val feedFile = File(context.cacheDir, "feed-" + (phone.ui.value.member?.group?.groupX?.take(16) ?: phone.slot) + ".json")

    /** Called once the whole object is set up: the filters below need it. */
    private fun restoreFeed() {
        scope.launch {
            loadTranslations()
            val m = try { Json.parse(feedFile.readText()) as? Map<*, *> } catch (_: Exception) { null } ?: return@launch
            val notes = (m["notes"] as? List<*>)?.mapNotNull { Event.fromMap(it) }?.filter { Curate.keep(it) && forDiscover(it) }?.let { Curate.page(it) } ?: return@launch
            if (notes.isEmpty()) return@launch
            remember(notes)
            feed.update { if (it.notes.isNotEmpty()) it else it.copy(notes = notes, source = m["source"] as? String, at = m["at"] as? Long ?: 0) }
            afterPaint()
            People.want(notes.map { it.pubkey })
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
            val got = Fetch.query(listOf(src), mapOf("kinds" to FEED_KINDS, "limit" to 60, "until" to until), 8000)
            val ok = got.filter { it.kind in FEED_KINDS && Curate.keep(it) && forDiscover(it) && f.notes.none { n -> n.id == it.id } }
            val more = Curate.page(if (src == Sources.FEEDS[0]) ok else ok.sortedByDescending { it.createdAt }, already = f.notes)
            remember(more)
            People.want(more.map { it.pubkey })
            feed.update { it.copy(notes = it.notes + more, loading = false, more = got.isNotEmpty()) }
            translateIn(got.filter { it.kind in FEED_KINDS && Curate.keep(it) && foreignOk(it) })
        }
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
            afterPaint()
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

    /**
     * Search: people and posts. Your follows whose names match come first, at once; then what the
     * search relays find, each as it answers (none is dropped for being slow); then the order settles
     * as names, NIP-05s and trust come in. A #tag searches posts only.
     */
    fun search(q: String) {
        val text = q.trim()
        if (text.isEmpty()) return
        if (found.value?.query == text && found.value?.loading == true) return
        searching?.cancel()
        val gen = searchGen.incrementAndGet()
        found.value = Found(text)
        val t0 = android.os.SystemClock.uptimeMillis()
        // Debug builds only: what was searched and who came up are the user's business, not the log's.
        fun mark(what: String) = if (!debuggable || searchGen.get() != gen) Unit else android.util.Log.i("CosignSearch", "\"$text\" $what at ${android.os.SystemClock.uptimeMillis() - t0} ms; top: " +
            found.value?.people?.take(3)?.joinToString { pk -> (People.known.value[pk]?.shown ?: pk.take(8)) + " " + pk.take(8) })
        searching = scope.launch {
            val tag = text.removePrefix("#").takeIf { text.startsWith("#") && it.isNotBlank() && !it.contains(' ') }?.lowercase()
            val hits = ConcurrentHashMap<String, Hit>()
            val notes = java.util.Collections.synchronizedList(ArrayList<Event>())
            val order = java.util.concurrent.atomic.AtomicInteger()
            val mine = follows.value ?: emptySet()
            var first: String? = null
            fun show(loading: Boolean) {
                if (searchGen.get() != gen) return
                val people = SearchRank.sort(hits.values.filter { it.pubkey !in muted.value }, text).take(30)
                people.firstOrNull()?.pubkey?.takeIf { it != first }?.let { pk -> first = pk; mark("first is now ${People.known.value[pk]?.shown ?: ""} ${pk.take(8)}") }
                val posts = synchronized(notes) { notes.distinctBy { it.id }.sortedByDescending { it.createdAt }.take(60) }
                found.value = Found(text, people.map { it.pubkey }, posts, loading, people.associateBy { it.pubkey })
            }
            // Until trust is known, the order the relays give, syb.lol's before relay.ditto.pub's before the slower ones'.
            fun add(pk: String, name: String?, rank: Int = 9) { hits.putIfAbsent(pk, Hit(pk, name, rank * 1000 + order.getAndIncrement(), follow = pk in mine)) }

            val relayJobs = ArrayList<kotlinx.coroutines.Job>()
            // What arrives (a count, a checked address) only marks the list changed; it's redrawn at most five times a second.
            val dirty = java.util.concurrent.atomic.AtomicBoolean(false)
            val redraw = launch { while (true) { delay(200); if (dirty.getAndSet(false)) show(true) } }
            // Trust is looked up one batch after another, so each relay sees one counting connection at a time.
            val toEnrich = kotlinx.coroutines.channels.Channel<List<Person>>(kotlinx.coroutines.channels.Channel.UNLIMITED)
            val enricher = launch { for (batch in toEnrich) enrich(batch, text, hits) { dirty.set(true) } }
            if (tag == null) {
                // Your follows, from what this phone knows: no waiting.
                People.known.value.values.filter { it.pubkey in mine && SearchRank.matches(it.name, text) }.forEach { add(it.pubkey, it.name) }
                show(true); mark("follows: ${hits.size}")
                // name@domain: whoever it names, at the top.
                if (Nip05.isAddress(text)) relayJobs += launch {
                    val pk = Nip05.lookup(text)?.takeIf { isHex32(it) } ?: return@launch
                    People.want(listOf(pk))
                    hits[pk] = Hit(pk, People.known.value[pk]?.name, -1, follow = pk in mine, nip05 = Nip05.Check.OK)
                    show(true); mark("address found")
                }
                val relays = SearchRelays.FAST.map { it to 8000L } + SearchRelays.SLOW.map { it to 3500L } + Sources.extra.value.map { it to 3000L }
                for ((i, rw) in relays.withIndex()) relayJobs += launch {
                    val (url, wait) = rw
                    val evs = Fetch.query(listOf(url), mapOf("kinds" to listOf(0), "search" to text, "limit" to 50), wait).filter { it.kind == 0 }
                    People.add(evs)
                    val fresh = evs.mapNotNull { e -> Person.of(e)?.takeIf { !hits.containsKey(it.pubkey) } }
                    fresh.forEach { add(it.pubkey, it.name, i) }
                    show(true); mark("${url.removePrefix("wss://")}: ${evs.size} people")
                    // Trust for the ones whose names match: those are the ones whose order matters.
                    val named = fresh.filter { SearchRank.matches(it.name, text) }
                    if (named.isNotEmpty()) toEnrich.send(named.take(30))
                }
            }
            // Posts: the fast relays together, the slow ones on their own.
            val noteFilter: Map<String, Any> = if (tag != null) mapOf("kinds" to listOf(1), "#t" to listOf(tag), "limit" to 40) else mapOf("kinds" to listOf(1), "search" to text, "limit" to 40)
            for ((relays, wait) in listOf((SearchRelays.FAST + if (tag != null) Sources.GENERAL else emptyList()) to 8000L, SearchRelays.SLOW to 3500L)) relayJobs += launch {
                val got = Fetch.query(relays + Sources.extra.value, noteFilter, wait).filter { it.kind == 1 }
                remember(got)
                notes += got.filter { safe(it) }
                People.want(got.map { it.pubkey })
                show(true); mark("posts from ${relays.size} relays: ${got.size}")
            }
            // The people your follows follow, once per run: the strongest sign of who's real to you.
            if (tag == null) relayJobs += launch {
                val f = friendsOfFriends()
                if (f.isEmpty()) return@launch
                hits.replaceAll { _, h -> h.copy(fof = f[h.pubkey] ?: 0) }
                show(true); mark("friends of friends")
            }
            relayJobs.joinAll()
            toEnrich.close(); enricher.join(); redraw.cancel()
            People.want(hits.keys.toList())
            show(false); mark("done")
        }
    }

    /** Follower counts and NIP-05 checks for people a search just found, filled into [hits] as they come. */
    private suspend fun enrich(people: List<Person>, query: String, hits: ConcurrentHashMap<String, Hit>, changed: () -> Unit) = kotlinx.coroutines.withTimeoutOrNull(6500) { kotlinx.coroutines.coroutineScope {
        // Each count and each check counts as soon as it's in: no waiting for the slowest.
        for (url in SearchRelays.COUNTS) launch {
            Fetch.counts(url, people.associate { it.pubkey to mapOf("kinds" to listOf(3), "#p" to listOf(it.pubkey)) }, 6000, inFlight = 15) { pk, c ->
                hits.computeIfPresent(pk) { _, h -> if ((h.followers ?: -1) >= c) h else h.copy(followers = c) }; changed()
            }
        }
        // Addresses checked for the exact names only (the order among those is what they decide), within a few seconds.
        val gate = kotlinx.coroutines.sync.Semaphore(8)
        people.filter { it.nip05 != null && SearchRank.exact(it.name, query) }.take(12).map { p ->
            async { gate.withPermit { Nip05.check(p.pubkey, p.nip05) }.also { c -> hits.computeIfPresent(p.pubkey) { _, h -> h.copy(nip05 = c) }; changed() } }
        }.awaitAll()
    }
    }

    private val searchGen = java.util.concurrent.atomic.AtomicInteger()
    private val debuggable = CosignApp.instance.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
    @Volatile private var fofCache: Map<String, Int>? = null
    /** For each person, how many of the people you follow follow them (from up to 300 follow lists). */
    private suspend fun friendsOfFriends(): Map<String, Int> {
        fofCache?.let { return it }
        val mine = follows.value?.toList()?.take(300) ?: return emptyMap()
        if (mine.isEmpty()) return emptyMap()
        val lists = mine.chunked(100).map { part -> scope.async { Fetch.query(Sources.PROFILES.take(3), mapOf("kinds" to listOf(3), "authors" to part), 6000) } }.awaitAll().flatten()
        val count = HashMap<String, Int>()
        lists.filter { it.kind == 3 }.groupBy { it.pubkey }.values.map { l -> l.maxBy { it.createdAt } }
            .forEach { l -> l.tags.filter { it.size > 1 && it[0] == "p" }.map { it[1] }.distinct().forEach { count[it] = (count[it] ?: 0) + 1 } }
        return count.also { fofCache = it }
    }

    fun clearSearch() { searching?.cancel(); searchGen.incrementAndGet(); found.value = null }

    // --- Threads and profiles --------------------------------------------------------

    /** Threads opened lately, so going back to one shows it at once. */
    private val threads = object : LinkedHashMap<String, List<Pair<Event, Int>>>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, List<Pair<Event, Int>>>?) = size > 30
    }

    /** What can be shown of thread [id] right now, with no network: as opened before, or the note itself (under its first note, if that's here). Null if neither is. */
    fun threadNow(id: String): List<Pair<Event, Int>>? {
        synchronized(threads) { threads[id] }?.let { return it }
        val n = note(id) ?: return null
        val root = rootOf(n)?.let { note(it) }
        return if (root != null && root.id != n.id) listOf(root to 0, n to 1) else listOf(n to 0)
    }

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
        synchronized(threads) { threads[id] = out }
        return out
    }

    /**
     * What someone posted, newest first: their posts, reposts and videos, read from the relays
     * they say they write to (their outbox) as well as the usual ones. [until]: older than this, for the next page.
     */
    suspend fun notesBy(pk: String, until: Long? = null): List<Event> {
        People.want(listOf(pk))
        val outbox = outboxOf(pk)
        val filter = buildMap<String, Any> { put("kinds", listOf(1, 6, 21, 22)); put("authors", listOf(pk)); put("limit", 30); until?.let { put("until", it - 1) } }
        val ns = Fetch.query((outbox + readRelays().take(3) + Sources.PROFILES.take(2)).distinct(), filter, 7000).filter { it.pubkey == pk }
        // Reposts carry what they repost; anything they only point at is fetched.
        val inner = ns.filter { it.kind == 6 }.mapNotNull { r -> reposted(r) }
        val missing = ns.filter { it.kind == 6 && reposted(it) == null }.mapNotNull { it.firstTag("e") }.filter { note(it) == null }
        if (missing.isNotEmpty()) remember(Fetch.query(readRelays() + outbox, mapOf("ids" to missing.take(30)), 5000))
        remember(ns.filter { it.kind != 6 } + inner)
        People.want(inner.map { it.pubkey })
        return ns.sortedByDescending { it.createdAt }
    }

    /** The post a repost (kind 6) carries in its content, if it's there and genuine; else the one it points at, if it's been seen. */
    fun reposted(r: Event): Event? = (try { Event.fromMap(Json.parse(r.content))?.takeIf { it.kind == 1 && it.verify() } } catch (_: Exception) { null })
        ?: r.firstTag("e")?.let { note(it) }

    /** The relays someone says they write to (their NIP-65 list): up to four. */
    private val outboxes = ConcurrentHashMap<String, List<String>>()
    private suspend fun outboxOf(pk: String): List<String> = outboxes[pk] ?: run {
        val l = Fetch.query(Sources.PROFILES.take(3), mapOf("kinds" to listOf(10002), "authors" to listOf(pk), "limit" to 1), 4000).maxByOrNull { it.createdAt }
        (l?.tags?.filter { it.size > 1 && it[0] == "r" && it.getOrNull(2) != "read" && it[1].startsWith("wss://") }?.map { it[1] }?.take(4) ?: emptyList()).also { outboxes[pk] = it }
    }

    /** The relays someone reads from (their inbox): where a reply or a reaction to them should go. */
    private suspend fun inboxOf(pk: String): List<String> {
        val l = Fetch.query(Sources.PROFILES.take(3), mapOf("kinds" to listOf(10002), "authors" to listOf(pk), "limit" to 1), 4000).maxByOrNull { it.createdAt }
        return l?.tags?.filter { it.size > 1 && it[0] == "r" && it.getOrNull(2) != "write" && it[1].startsWith("wss://") }?.map { it[1] }?.take(3) ?: emptyList()
    }

    // --- Replying and reporting ----------------------------------------------------------

    /**
     * Reply to [parent] (NIP-10: the thread's first post as root, the post you answer as reply,
     * everyone in the conversation tagged), sent to your relays and the author's. The reply, once sent; null if it wasn't.
     */
    suspend fun reply(parent: Event, text: String): Event? {
        val me = me ?: return null
        val body = text.trim().ifEmpty { return null }
        val root = rootOf(parent) ?: parent.id
        val tags = buildList {
            add(listOf("e", root, "", "root"))
            if (root != parent.id) add(listOf("e", parent.id, "", "reply"))
            (listOf(parent.pubkey) + parent.tags.filter { it.size > 1 && it[0] == "p" }.map { it[1] }).distinct().filter { it != me && cc.aaro.cosign.core.isHex32(it) }
                .forEach { add(listOf("p", it)) }
        }
        val signed = actEvent(Event(me, Clock.now(), 1, tags, body).withId(), relays = writeRelays() + inboxOf(parent.pubkey)) ?: return null
        remember(listOf(signed))
        // In the thread it was written in, under the post it answers, at once.
        synchronized(threads) {
            for ((k, list) in threads.entries.toList()) {
                val i = list.indexOfFirst { it.first.id == parent.id }.takeIf { it >= 0 } ?: continue
                val depth = list[i].second
                var end = i + 1
                while (end < list.size && list[end].second > depth) end++
                threads[k] = list.take(end) + (signed to depth + 1) + list.drop(end)
            }
        }
        return signed
    }

    /** NIP-56: report a post and its author (spam, nudity, illegal, impersonation, other), and stop showing it. */
    fun report(n: Event, reason: String) {
        val me = me ?: return
        notInterested(n)
        scope.launch {
            val tags = listOf(listOf("e", n.id, reason), listOf("p", n.pubkey, reason))
            if (act(Event(me, Clock.now(), 1984, tags, "").withId())) message.value = "Reported. Thanks for telling us."
        }
    }

    // --- Notifications ---------------------------------------------------------------

    fun loadNotices(force: Boolean = false) {
        val me = me ?: return
        val n = notices.value
        if (n.loading || (!force && n.at != 0L && System.currentTimeMillis() - n.at < 5 * 60_000)) return
        notices.update { it.copy(loading = true) }
        scope.launch {
            afterPaint()
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
    fun safe(e: Event) = !Safety.flagged(e) && e.pubkey !in muted.value && e.id !in dismissed.value && !mutedText(e.content, e)
    /** In Discover, also only in a language this phone is set to, or translated into it. */
    private fun forDiscover(e: Event) = safe(e) && !snoozedNow(e.pubkey) && (Lang.readable(e, languages) || translations.value[e.id]?.let { okText(it.text) } == true)
    /** In another language, and fine otherwise: worth translating. */
    private fun foreignOk(e: Event) = Translate.on && safe(e) && !snoozedNow(e.pubkey) && !Lang.readable(e, languages) && e.id !in translations.value

    /** Words and hashtags you muted (your mute list's "word" and "t" entries). */
    val mutedWords = MutableStateFlow(prefs.getStringSet("mutedWords", emptySet())!!.toSet())
    private fun mutedText(text: String, e: Event? = null): Boolean {
        val words = mutedWords.value
        if (words.isEmpty()) return false
        val lower = text.lowercase()
        return words.any { w -> if (w.startsWith("#")) e?.tags?.any { it.size > 1 && it[0] == "t" && it[1].lowercase() == w.drop(1) } == true || "(?<![\\p{L}\\p{N}_])${Regex.escape(w)}(?![\\p{L}\\p{N}_])".toRegex().containsMatchIn(lower) else lower.contains(w) }
    }
    /** A translation passes the same text filters as an original: adult hashtags, muted words. */
    private fun okText(text: String) = !Safety.flaggedText(text) && !mutedText(text)

    // --- Translations (your LibreTranslate, if you set one) ---------------------------------

    /** A note's text in this phone's language, and the language it was in (null: it was in yours after all). */
    data class Translated(val text: String, val from: String?)
    val translations = MutableStateFlow<Map<String, Translated>>(emptyMap())
    private val translationsFile = File(context.cacheDir, "translations-" + (phone.ui.value.member?.group?.groupX?.take(16) ?: phone.slot) + ".json")

    private fun loadTranslations() {
        val m = try { Json.parse(translationsFile.readText()) as? Map<*, *> } catch (_: Exception) { null } ?: return
        translations.value = m.entries.mapNotNull { (k, v) -> val x = v as? Map<*, *> ?: return@mapNotNull null; (k as String) to Translated(x["text"] as? String ?: return@mapNotNull null, x["from"] as? String) }.toMap()
    }

    /** Translate these, in one request, in the background; the ones that pass go in below what's on screen. */
    private fun translateIn(notes: List<Event>) {
        if (notes.isEmpty() || !Translate.on) return
        scope.launch {
            afterPaint()
            val todo = notes.distinctBy { it.id }.take(40)
            val target = Translate.target()
            val out = Translate.batch(todo.map { it.content.take(1500) }, target) ?: return@launch
            val got = todo.zip(out).associate { (e, r) -> e.id to Translated(r.first, r.second?.takeIf { it != target }) }
            translations.update { (it + got).entries.toList().takeLast(600).associate { (k, v) -> k to v } }
            try { translationsFile.writeText(Json.stringify(translations.value.mapValues { (_, t) -> mapOf("text" to t.text, "from" to t.from) })) } catch (_: Exception) {}
            val add = todo.filter { e -> got[e.id]?.let { okText(it.text) && !Curate.heavy(it.text) } == true }
            if (add.isEmpty()) return@launch
            remember(add)
            People.want(add.map { it.pubkey })
            // Below what's on screen, by time among the rest; nothing you're looking at moves.
            feed.update { cur ->
                val keep = cur.notes.take(lookedAt + 3)
                val rest = (cur.notes.drop(keep.size) + add.filter { a -> cur.notes.none { it.id == a.id } }).sortedByDescending { it.createdAt }
                cur.copy(notes = keep + rest)
            }
            saveFeed()
        }
    }

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
        val words = list.tags.filter { it.size > 1 && (it[0] == "word" || it[0] == "t") }.map { (if (it[0] == "t") "#" else "") + it[1].lowercase() }.filter { it.length > 1 }.toSet()
        mutedWords.value = words
        prefs.edit().putStringSet("mutedWords", words).apply()
    }

    private suspend fun knowFollows() {
        if (follows.value != null) return
        val c = newestContacts(fetch = true)
        contacts = c
        follows.value = followsIn(c)
    }

    /** Your servers sign it (or hand it to you to approve), then it goes to your relays. */
    private suspend fun act(ev: Event, approved: Boolean = false): Boolean = actEvent(ev, approved) != null

    /** Your servers sign it (or hand it to you to approve), then it goes to [relays] (yours by default). What was sent, or null. */
    private suspend fun actEvent(ev: Event, approved: Boolean = false, relays: List<String>? = null): Event? {
        val signed = try { phone.signOwn(ev, approved) } catch (e: NeedsApproval) {
            held.value = Held(e.what, ev); return null
        } catch (e: Exception) {
            message.value = "Couldn't do that right now: ${e.message ?: "no answer"}"; return null
        }
        if (signed.kind == 3) { contacts = signed; follows.value = followsIn(signed) }
        if (signed.kind == 10000) mutes = signed
        val n = Fetch.publish(if (Sources.localOnly) Sources.extra.value else (relays ?: writeRelays()).distinct().take(10), signed)
        if (n == 0) message.value = "Couldn't send that right now. Try again later."
        return signed.takeIf { n > 0 }
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
