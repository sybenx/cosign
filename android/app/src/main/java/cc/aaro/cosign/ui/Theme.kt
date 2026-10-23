package cc.aaro.cosign.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import cc.aaro.cosign.R

// "Vault": warm black, amber wherever a key leaves this phone, teal wherever one
// arrives. Amber is never used for "verified" or "safe" (§11.2b).

object Vault {
    val Ground = Color(0xFF13110F)
    val Surface = Color(0xFF1E1B18)
    val Edge = Color(0xFF2A2622)
    val Line = Color(0xFF34302B)
    val Field = Color(0xFF4A443C)
    val Text = Color(0xFFEDE6DA)
    val Muted = Color(0xFFA69D90)
    val Amber = Color(0xFFF2B33D)
    val OnAmber = Color(0xFF1A1406)
    val AmberEdge = Color(0xFF5A4520)
    val AmberText = Color(0xFFE9CF97)
    val AmberGround = Color(0xFF221A0D)
    val Teal = Color(0xFF7FC8C0)
    val TealEdge = Color(0xFF2F4A47)
    val TealGround = Color(0xFF16201F)
    val Danger = Color(0xFFE5736B)
}

// Kept for the few places that name the direction's color directly.
val Release = Vault.Amber
val Receipt = Vault.Teal
val Danger = Vault.Danger

@OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)
private fun sans(weight: Int) = Font(
    R.font.ibmplexsans_variable,
    weight = FontWeight(weight),
    variationSettings = FontVariation.Settings(FontVariation.weight(weight)),
)

val PlexSans = FontFamily(sans(400), sans(500), sans(600), sans(700))
val PlexMono = FontFamily(
    Font(R.font.ibmplexmono_regular, FontWeight.Normal),
    Font(R.font.ibmplexmono_medium, FontWeight.Medium),
)

private val scheme = darkColorScheme(
    primary = Vault.Text,
    onPrimary = Vault.Ground,
    secondary = Vault.Teal,
    background = Vault.Ground,
    surface = Vault.Ground,
    surfaceVariant = Vault.Surface,
    surfaceContainerHigh = Vault.Surface,
    onSurface = Vault.Text,
    onSurfaceVariant = Vault.Muted,
    outline = Vault.Line,
    error = Vault.Danger,
)

private val type = Typography(
    headlineMedium = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.SemiBold, fontSize = 32.sp, lineHeight = 38.sp),
    headlineSmall = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.SemiBold, fontSize = 28.sp, lineHeight = 33.sp),
    titleLarge = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp),
    titleMedium = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.Medium, fontSize = 17.sp, lineHeight = 23.sp),
    titleSmall = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 20.sp),
    bodyLarge = TextStyle(fontFamily = PlexSans, fontSize = 17.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontFamily = PlexSans, fontSize = 15.sp, lineHeight = 21.sp),
    bodySmall = TextStyle(fontFamily = PlexSans, fontSize = 13.sp, lineHeight = 18.sp),
    labelLarge = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.Medium, fontSize = 16.sp, lineHeight = 20.sp),
    labelMedium = TextStyle(fontFamily = PlexSans, fontWeight = FontWeight.Medium, fontSize = 14.sp),
)

@Composable
fun CosignTheme(content: @Composable () -> Unit) = MaterialTheme(colorScheme = scheme, typography = type, content = content)
