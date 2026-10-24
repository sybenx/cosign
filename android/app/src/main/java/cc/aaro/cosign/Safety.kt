package cc.aaro.cosign

import cc.aaro.cosign.core.Event

// What Discover leaves out by default: notes marked sensitive, and notes in a language this
// phone isn't set to. Both are cheap and run on every note as it arrives.

object Safety {
    private val NSFW = setOf("nsfw", "nude", "nudes", "nudity", "porn", "xxx", "18+", "onlyfans", "lewd", "hentai")
    private val NSFW_TEXT = Regex("(?i)(?<![\\p{L}\\p{N}_])#(nsfw|nude|nudes|nudity|porn|xxx|onlyfans|lewd|hentai)(?![\\p{L}\\p{N}_])")

    /** A NIP-36 content warning, or tagged as adult (a #t, a NIP-32 label, or a #hashtag in the text). */
    fun flagged(e: Event): Boolean = e.tags.any { t ->
        t.isNotEmpty() && when (t[0]) {
            "content-warning" -> true
            "t" -> t.getOrNull(1)?.lowercase() in NSFW
            "l" -> t.getOrNull(1)?.lowercase()?.let { it in NSFW || it.startsWith("ns-") || it == "porn" } == true
            else -> false
        }
    } || NSFW_TEXT.containsMatchIn(e.content)

    /** The text alone (a translation): adult #hashtags in it. */
    fun flaggedText(text: String) = NSFW_TEXT.containsMatchIn(text)
}

object Lang {
    /** The languages this phone is set to, as two-letter codes (with Java's old names for Hebrew and Indonesian). */
    fun phone(): Set<String> {
        val list = android.os.LocaleList.getDefault()
        return (0 until list.size()).map { list[it].language.lowercase() }.flatMap { listOf(it) + (OLD[it] ?: emptyList()) }.toSet().ifEmpty { setOf("en") }
    }
    private val OLD = mapOf("he" to listOf("iw"), "iw" to listOf("he"), "id" to listOf("in"), "in" to listOf("id"))

    /** Whether someone reading [langs] can read it. Unsure means yes: only a clear guess hides a note. */
    fun readable(e: Event, langs: Set<String>): Boolean {
        val l = labelled(e)?.let { setOf(it) } ?: guess(e.content) ?: return true
        return l.any { it in langs }
    }

    /** NIP-32: ["l", "en", "ISO-639-1"]. */
    private fun labelled(e: Event): String? = e.tags.firstOrNull { it.size >= 3 && it[0] == "l" && it[2] == "ISO-639-1" }?.get(1)?.lowercase()?.take(2)

    private val STRIP = Regex("https?://\\S+|nostr:\\S+|[#@]\\S+|:[a-z0-9_]+:")

    /** The languages a text is most likely in, or null when it's too short or too mixed to say. */
    fun guess(text: String): Set<String>? {
        val t = STRIP.replace(text, " ")
        var latin = 0; var cyr = 0; var greek = 0; var arabic = 0; var hebrew = 0; var deva = 0; var thai = 0; var hangul = 0; var kana = 0; var han = 0
        var i = 0
        while (i < t.length) {
            val cp = t.codePointAt(i); i += Character.charCount(cp)
            if (!Character.isLetter(cp)) continue
            when (Character.UnicodeScript.of(cp)) {
                Character.UnicodeScript.LATIN -> latin++
                Character.UnicodeScript.CYRILLIC -> cyr++
                Character.UnicodeScript.GREEK -> greek++
                Character.UnicodeScript.ARABIC -> arabic++
                Character.UnicodeScript.HEBREW -> hebrew++
                Character.UnicodeScript.DEVANAGARI -> deva++
                Character.UnicodeScript.THAI -> thai++
                Character.UnicodeScript.HANGUL -> hangul++
                Character.UnicodeScript.HIRAGANA, Character.UnicodeScript.KATAKANA -> kana++
                Character.UnicodeScript.HAN -> han++
                else -> {}
            }
        }
        val total = latin + cyr + greek + arabic + hebrew + deva + thai + hangul + kana + han
        if (total < 8) return null
        fun most(n: Int) = n * 2 > total
        return when {
            kana > 0 && most(kana + han) -> setOf("ja")
            most(han) -> setOf("zh", "ja")
            most(hangul) -> setOf("ko")
            most(cyr) -> setOf("ru", "uk", "bg", "sr", "mk", "be", "kk")
            most(arabic) -> setOf("ar", "fa", "ur")
            most(hebrew) -> setOf("he", "iw", "yi")
            most(deva) -> setOf("hi", "mr", "ne")
            most(thai) -> setOf("th")
            most(greek) -> setOf("el")
            most(latin) -> latinGuess(t)
            else -> null
        }
    }

    // Common little words, enough to tell the usual Latin-script languages apart on Nostr.
    private val WORDS = mapOf(
        "en" to "the and is are you that this with for have not was what just it's i'm my your but they will be of to in on it".split(' '),
        "de" to "der die das und ist nicht ich ein eine mit auf für sie wir auch sich dem den zu es aber noch wie bin hat".split(' '),
        "es" to "el la los las que de y es en por para con una un pero más como muy del se lo está yo hay también".split(' '),
        "pt" to "o a os as que de e é em um uma para com não mais mas do da dos das você eu tem sempre isso está também".split(' '),
        "fr" to "le la les et est un une des du de que pas pour dans ce qui sur avec je vous il elle c'est mais très".split(' '),
        "it" to "il la e è di che un una per non con sono del della mi ma anche questo ho si molto".split(' '),
        "nl" to "de het een en is van niet ik dat je op met voor zijn maar ook wat er heb".split(' '),
    ).mapValues { it.value.toSet() }

    private val NOT_LETTERS = Regex("[^\\p{L}']+")

    private fun latinGuess(t: String): Set<String>? {
        val words = t.lowercase().split(NOT_LETTERS).filter { it.isNotEmpty() }
        if (words.size < 4) return null
        val scores = WORDS.mapValues { (_, w) -> words.count { it in w } }.entries.sortedByDescending { it.value }
        val (best, second) = scores[0] to scores[1]
        // Sure enough: a few hits, and clearly ahead of the next.
        return if (best.value >= 2 && best.value >= second.value * 1.5 && best.value * 8 >= words.size) setOf(best.key) else null
    }
}
