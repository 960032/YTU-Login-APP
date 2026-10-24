package top.ytu.srunautologin.flow

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import top.ytu.srunautologin.auth.AuthTransport

/** Probe and authentication share the same captured network for this run. */
class AuthSession(
    val transport: AuthTransport,
    val probe: ProbePort,
    private val release: () -> Unit = {}
) : Closeable {
    private val closed = AtomicBoolean(false)
    override fun close() { if (closed.compareAndSet(false, true)) release() }
}

fun interface AuthSessionFactory {
    @Throws(IOException::class)
    fun open(ssid: String): AuthSession
}

/** Coalesces simultaneous manual, network-event and scheduled authentications. */
internal object AuthenticationGate {
    private val running = AtomicBoolean(false)
    fun tryEnter(): Boolean = running.compareAndSet(false, true)
    fun leave() { running.set(false) }
}
