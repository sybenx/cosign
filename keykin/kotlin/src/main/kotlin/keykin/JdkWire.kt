// The relays' WebSocket on the JVM: the JDK's own client, so the desktop build needs no dependency.
// Android uses OkHttp (keykin-android's OkWire) behind the same `Wire`.
package keykin

import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.util.concurrent.CompletionStage
import java.util.concurrent.TimeUnit

object JdkWire : Wire {
    private val client = HttpClient.newHttpClient()
    override fun open(url: String, onText: (String) -> Unit, onClosed: () -> Unit): WireSocket {
        val ws = client.newWebSocketBuilder().buildAsync(URI(url), object : WebSocket.Listener {
            private val buf = StringBuilder()
            override fun onText(ws: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
                buf.append(data)
                if (last) { val s = buf.toString(); buf.setLength(0); onText(s) }
                ws.request(1); return null
            }
            override fun onClose(ws: WebSocket, code: Int, reason: String): CompletionStage<*>? { onClosed(); return null }
            override fun onError(ws: WebSocket, error: Throwable) = onClosed()
        }).get(10, TimeUnit.SECONDS)
        return object : WireSocket {
            // One frame at a time: the JDK client refuses a send while another is pending.
            override fun send(text: String): Boolean = try { synchronized(this) { ws.sendText(text, true).get(5, TimeUnit.SECONDS) }; true } catch (_: Exception) { false }
            override fun close() { try { ws.sendClose(WebSocket.NORMAL_CLOSURE, "").get(2, TimeUnit.SECONDS) } catch (_: Exception) {} }
        }
    }
}
