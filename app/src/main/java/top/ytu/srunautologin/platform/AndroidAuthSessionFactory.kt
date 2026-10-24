package top.ytu.srunautologin.platform

import android.content.Context
import android.net.Network
import java.util.concurrent.ConcurrentHashMap
import top.ytu.srunautologin.auth.HttpUrlConnectionEngine
import top.ytu.srunautologin.auth.SocketLocalIpProbe
import top.ytu.srunautologin.auth.SrunAuthClient
import top.ytu.srunautologin.flow.AuthSession
import top.ytu.srunautologin.flow.AuthSessionFactory
import top.ytu.srunautologin.flow.SrunPortalProbe
import top.ytu.srunautologin.log.AppLog

/** Only active sessions hold connections; stopping automatic mode leaves manual requests alone. */
object ActiveWifiSessions {
    private data class Owner(val thread: Thread, val automatic: Boolean)
    private val sessions = ConcurrentHashMap<WifiFirstConnectionFactory, Owner>()
    fun register(binding: WifiFirstConnectionFactory, automatic: Boolean) {
        sessions[binding] = Owner(Thread.currentThread(), automatic)
    }
    fun release(binding: WifiFirstConnectionFactory) { sessions.remove(binding); binding.close() }
    fun cancelAll() { sessions.keys.forEach { it.close() } }
    fun cancelAutomatic() { sessions.forEach { (binding, owner) -> if (owner.automatic) binding.close() } }
    fun cancelThread(thread: Thread) { sessions.forEach { (binding, owner) -> if (owner.thread === thread) binding.close() } }
    fun cancelNetwork(network: Network) { sessions.keys.forEach { if (it.isBoundTo(network)) it.close() } }
}

class AndroidAuthSessionFactory(context: Context, private val automatic: Boolean) : AuthSessionFactory {
    private val appContext = context.applicationContext

    override fun open(ssid: String): AuthSession {
        val binding = WifiFirstConnectionFactory(appContext, ssid)
        val sockets = WifiSocketFactoryProvider(binding)
        val engine = HttpUrlConnectionEngine(connectionFactory = binding, log = { line ->
            AppLog.record(SrunStorage.keyValueStore(appContext), "$line | ${binding.networkDescription()}")
        })
        ActiveWifiSessions.register(binding, automatic)
        return AuthSession(
            SrunAuthClient(engine, SocketLocalIpProbe(sockets)),
            SrunPortalProbe(engine, timeoutMs = 5_000, socketFactory = sockets)
        ) { ActiveWifiSessions.release(binding) }
    }
}
