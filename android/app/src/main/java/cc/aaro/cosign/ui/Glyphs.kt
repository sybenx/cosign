package cc.aaro.cosign.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

/** The card's line icons, drawn from the same paths as discover.syb.lol's (24 × 24, round strokes); tinted where they're used. */
object Glyphs {
    private fun line(name: String, d: String, fill: Boolean = false) = ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).addPath(
        PathParser().parsePathString(d).toNodes(),
        fill = if (fill) SolidColor(Color.White) else null,
        stroke = SolidColor(Color.White), strokeLineWidth = 1.8f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round,
    ).build()

    private const val HEART = "M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1-1.1a5.5 5.5 0 0 0-7.8 7.8l1 1.1L12 21l7.8-7.5 1-1.1a5.5 5.5 0 0 0 0-7.8z"
    val heart = line("heart", HEART)
    val heartOn = line("heartOn", HEART, fill = true)
    val reply = line("reply", "M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z")
    val smile = line("smile", "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18zM8.5 14.5a4.5 4.5 0 0 0 7 0M9 9.5h.01M15 9.5h.01")
    val lang = line("lang", "M4 5h9M8.5 3v2M6 5c1 3.5 3.5 6 7 7.5M11 5c-1 4-3.5 7-7 8.5M13 21l4-9 4 9M14.5 18h5")
    val repost = line("repost", "M17 2l4 4-4 4M3 11V9a3 3 0 0 1 3-3h15M7 22l-4-4 4-4M21 13v2a3 3 0 0 1-3 3H3")
    val out = line("out", "M7 17 17 7M8 7h9v9")
    val warn = line("warn", "M12 3 2 20h20L12 3zM12 10v4M12 17h.01")
}
