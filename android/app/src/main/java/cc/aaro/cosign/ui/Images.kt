package cc.aaro.cosign.ui

import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import cc.aaro.cosign.CosignApp
import cc.aaro.cosign.net.Fetch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.Cache
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

/** Pictures in notes and profiles: fetched over https, cached on disk by OkHttp, scaled down to what's shown. */
object Images {
    private val http by lazy {
        Fetch.http.newBuilder().cache(Cache(File(CosignApp.instance.cacheDir, "images"), 40L * 1024 * 1024))
            .callTimeout(15, TimeUnit.SECONDS).build()
    }
    private val memory = object : LruCache<String, ImageBitmap>(24 * 1024 * 1024) {
        override fun sizeOf(key: String, value: ImageBitmap) = value.width * value.height * 4
    }
    private val failed = HashSet<String>()
    private val gate = Semaphore(4)
    private const val MAX_BYTES = 12L * 1024 * 1024

    fun cached(url: String, px: Int): ImageBitmap? = memory.get("$px $url")

    suspend fun load(url: String, px: Int): ImageBitmap? {
        val key = "$px $url"
        memory.get(key)?.let { return it }
        if (!url.startsWith("https://") || synchronized(failed) { url in failed }) return null
        return gate.withPermit {
            withContext(Dispatchers.IO) {
                try {
                    val bytes = http.newCall(Request.Builder().url(url).build()).execute().use { r ->
                        val body = r.body ?: return@use null
                        if (!r.isSuccessful || body.contentLength() > MAX_BYTES) null else body.source().let { s -> s.request(MAX_BYTES + 1); if (s.buffer.size > MAX_BYTES) null else s.readByteArray() }
                    } ?: error("no image")
                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                    var sample = 1
                    while (bounds.outWidth / (sample * 2) >= px) sample *= 2
                    val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample }) ?: error("not an image")
                    bmp.asImageBitmap().also { memory.put(key, it) }
                } catch (_: Exception) { synchronized(failed) { failed += url }; null }
            }
        }
    }
}

/** A picture from the web, or [placeholder] until (or unless) it arrives. */
@Composable
fun NetImage(url: String?, modifier: Modifier, px: Int, scale: ContentScale = ContentScale.Crop, description: String? = null, placeholder: @Composable () -> Unit = {}) {
    var img by remember(url, px) { mutableStateOf(url?.let { Images.cached(it, px) }) }
    LaunchedEffect(url, px) { if (img == null && url != null) img = Images.load(url, px) }
    val shown = img
    if (shown != null) Image(shown, description, modifier, contentScale = scale)
    else Box(modifier.background(Vault.Surface)) { placeholder() }
}
