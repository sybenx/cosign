package cc.aaro.cosign.ui

import android.graphics.SurfaceTexture
import android.view.TextureView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.media3.common.MediaItem
import androidx.media3.common.Player
import androidx.media3.common.VideoSize
import androidx.media3.exoplayer.ExoPlayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/** A video in a note: its address, a picture to show before it plays (if the note gave one), its shape and length. */
data class VideoRef(val url: String, val poster: String?, val ratio: Float, val seconds: Int?)

/**
 * One player for the whole app: one video plays at a time. Nothing loads before you tap ▶;
 * it's let go when its card leaves the screen, and paused when the app does.
 */
object Videos {
    /** What's playing (its address), and whether it's full screen. */
    val playing = mutableStateOf<VideoRef?>(null)
    val full = mutableStateOf(false)
    private var exo: ExoPlayer? = null

    fun player(context: android.content.Context): ExoPlayer = exo ?: ExoPlayer.Builder(context.applicationContext).build().also { p ->
        exo = p
        // At the end, back to the picture and ▶ (full screen waits for you to close it).
        p.addListener(object : Player.Listener { override fun onPlaybackStateChanged(state: Int) { if (state == Player.STATE_ENDED && !full.value) release() } })
    }

    fun play(context: android.content.Context, v: VideoRef) {
        val p = player(context)
        if (playing.value?.url != v.url) { p.setMediaItem(MediaItem.fromUri(v.url)); p.prepare() }
        p.volume = 1f // you tapped play: with sound
        p.play()
        playing.value = v
    }

    fun pause() = exo?.pause()

    /** Its card left the screen: stop and let the player go. Not while it's full screen. */
    fun leave(url: String) { if (playing.value?.url == url && !full.value) release() }

    fun release() { exo?.release(); exo = null; playing.value = null; full.value = false }

    // A frame to show when a note gives no picture for its video: taken only once the card is on
    // screen, one at a time, and kept (with the length) for as long as the app runs.
    private val frames = HashMap<String, Pair<ImageBitmap?, Int?>>()
    private val one = Semaphore(1)
    suspend fun frame(url: String): Pair<ImageBitmap?, Int?> {
        synchronized(frames) { frames[url] }?.let { return it }
        return one.withPermit {
            withContext(Dispatchers.IO) {
                val r = android.media.MediaMetadataRetriever()
                val got = try {
                    r.setDataSource(url, HashMap())
                    val secs = r.extractMetadata(android.media.MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull()?.let { (it / 1000).toInt() }
                    val bmp = r.getScaledFrameAtTime(0, android.media.MediaMetadataRetriever.OPTION_CLOSEST_SYNC, 720, 720)
                    bmp?.asImageBitmap() to secs
                } catch (_: Exception) { null to null } finally { try { r.release() } catch (_: Exception) {} }
                synchronized(frames) { frames[url] = got }
                got
            }
        }
    }
}

/** A video in a card: its picture and ▶ until tapped; then it plays here, with a button for full screen. */
@Composable
fun VideoCard(v: VideoRef, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val now = Videos.playing.value
    val here = now?.url == v.url && !Videos.full.value
    // Off screen (or gone): let the player go. The app in the background: pause.
    DisposableEffect(v.url) { onDispose { Videos.leave(v.url) } }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { if (now?.url == v.url) Videos.pause() }
    Box(modifier.fillMaxWidth().aspectRatio(v.ratio.coerceIn(0.56f, 2.2f)).clip(RoundedCornerShape(12.dp)).background(Color.Black)) {
        if (here) {
            Surface(Videos.player(context), Modifier.fillMaxSize())
            Controls(Videos.player(context), Modifier.align(Alignment.BottomCenter), onFull = { Videos.full.value = true }, fullLabel = "⤢")
        } else {
            var frame by remember(v.url) { mutableStateOf<Pair<ImageBitmap?, Int?>?>(null) }
            if (v.poster != null) NetImage(v.poster, Modifier.fillMaxSize(), 1080, ground = Color.Black)
            else {
                LaunchedEffect(v.url) { frame = Videos.frame(v.url) }
                frame?.first?.let { androidx.compose.foundation.Image(it, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop) }
            }
            Box(Modifier.align(Alignment.Center).size(64.dp).clip(CircleShape).background(Color(0x99000000)).clickable { Videos.play(context, v) }, contentAlignment = Alignment.Center) {
                Icon(Icons.Filled.PlayArrow, "Play", tint = Color.White, modifier = Modifier.size(40.dp))
            }
            (v.seconds ?: frame?.second)?.let { s ->
                Text(clock(s * 1000L), color = Color.White, style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.align(Alignment.BottomEnd).padding(8.dp).background(Color(0xCC000000), RoundedCornerShape(4.dp)).padding(horizontal = 6.dp, vertical = 2.dp))
            }
        }
    }
}

/** The playing video, full screen. Back, ✕ or the end of it closes. */
@Composable
fun VideoFullScreen() {
    val v = Videos.playing.value ?: return
    if (!Videos.full.value) return
    val context = LocalContext.current
    val close = { Videos.full.value = false; if (Videos.player(context).playbackState == Player.STATE_ENDED) Videos.release() }
    BackHandler(onBack = close)
    Box(Modifier.fillMaxSize().background(Color.Black)) {
        Surface(Videos.player(context), Modifier.align(Alignment.Center).fillMaxWidth())
        Controls(Videos.player(context), Modifier.align(Alignment.BottomCenter).safeDrawingPadding(), onFull = close, fullLabel = "⤡")
        Box(Modifier.align(Alignment.TopEnd).safeDrawingPadding().padding(12.dp).size(40.dp).clip(CircleShape).background(Color(0x66000000)).clickable(onClick = close),
            contentAlignment = Alignment.Center) { Icon(Icons.Filled.Close, "Close", tint = Color.White) }
    }
}

/** Where the picture goes: a TextureView (it scrolls with the list), the video's own shape inside [modifier]. */
@Composable
private fun Surface(p: ExoPlayer, modifier: Modifier) {
    var ratio by remember { mutableFloatStateOf(p.videoSize.let { if (it.height > 0) it.width * it.pixelWidthHeightRatio / it.height else 16f / 9f }) }
    DisposableEffect(p) {
        val l = object : Player.Listener { override fun onVideoSizeChanged(s: VideoSize) { if (s.height > 0) ratio = s.width * s.pixelWidthHeightRatio / s.height } }
        p.addListener(l); onDispose { p.removeListener(l) }
    }
    Box(modifier, contentAlignment = Alignment.Center) {
        AndroidView({ TextureView(it) }, Modifier.aspectRatio(ratio.coerceIn(0.3f, 4f)).clickable { if (p.isPlaying) p.pause() else p.play() },
            update = { tv -> p.setVideoTextureView(tv) }, onRelease = { tv -> p.clearVideoTextureView(tv) })
    }
}

/** Play or pause, where it is, how long, and full screen (or back from it). */
@Composable
private fun Controls(p: ExoPlayer, modifier: Modifier, onFull: () -> Unit, fullLabel: String) {
    var at by remember { mutableLongStateOf(0L) }
    var length by remember { mutableLongStateOf(0L) }
    var playing by remember { mutableStateOf(p.isPlaying) }
    var dragging by remember { mutableStateOf<Float?>(null) }
    LaunchedEffect(p) { while (true) { at = p.currentPosition; length = p.duration.coerceAtLeast(0); playing = p.isPlaying || p.playWhenReady && p.playbackState == Player.STATE_BUFFERING; delay(400) } }
    Row(modifier.fillMaxWidth().background(Color(0x99000000)).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(36.dp).clip(CircleShape).clickable { if (p.isPlaying) p.pause() else { if (p.playbackState == Player.STATE_ENDED) p.seekTo(0); p.play() } }, contentAlignment = Alignment.Center) {
            // Two bars for pause (the core icon set has no pause).
            if (playing) Row { repeat(2) { i -> if (i == 1) Spacer(Modifier.width(5.dp)); Box(Modifier.size(5.dp, 16.dp).background(Color.White)) } }
            else Icon(Icons.Filled.PlayArrow, "Play", tint = Color.White, modifier = Modifier.size(24.dp))
        }
        Text(clock(at), color = Color.White, style = MaterialTheme.typography.labelSmall)
        Slider(dragging ?: if (length > 0) at.toFloat() / length else 0f, { dragging = it }, Modifier.weight(1f).padding(horizontal = 8.dp),
            onValueChangeFinished = { dragging?.let { p.seekTo((it * length).toLong()) }; dragging = null },
            colors = SliderDefaults.colors(thumbColor = Color.White, activeTrackColor = Vault.Teal, inactiveTrackColor = Color(0x66FFFFFF)))
        Text(clock(length), color = Color.White, style = MaterialTheme.typography.labelSmall)
        Spacer(Modifier.width(4.dp))
        Text(fullLabel, color = Color.White, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.clip(CircleShape).clickable(onClick = onFull).padding(horizontal = 8.dp))
    }
}

private fun clock(ms: Long): String { val s = ms / 1000; return if (s >= 3600) "%d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60) else "%d:%02d".format(s / 60, s % 60) }
