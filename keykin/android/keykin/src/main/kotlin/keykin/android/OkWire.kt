// The relays' WebSocket on Android: OkHttp, behind the same `Wire` the JVM build fills with the JDK's client.
package keykin.android

import keykin.Wire
import keykin.WireSocket
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit

class OkWire(private val client: OkHttpClient = OkHttpClient.Builder().pingInterval(30, TimeUnit.SECONDS).build()) : Wire {
    override fun open(url: String, onText: (String) -> Unit, onClosed: () -> Unit): WireSocket {
        val ws = client.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) { try { onText(text) } catch (_: Exception) {} }
            // The relay is closing: close our side at once, so RelayNet redials instead of writing into it (L10).
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) { webSocket.close(1000, null); onClosed() }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = onClosed()
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = onClosed()
        })
        return object : WireSocket {
            override fun send(text: String): Boolean = ws.send(text)
            override fun close() { ws.close(1000, null) }
        }
    }
}
