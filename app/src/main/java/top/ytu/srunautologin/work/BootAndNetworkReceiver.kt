package top.ytu.srunautologin.work

import android.annotation.TargetApi
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import java.util.concurrent.ConcurrentHashMap
import top.ytu.srunautologin.platform.ActiveWifiSessions
import top.ytu.srunautologin.platform.WifiNetworkNames

/** Restores scheduling after a reboot/update; no fixed-time morning login is reintroduced. */
class AutoLoginRestoreReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent?.action !in setOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED)) return
        AutoLoginController.restore(context, intent?.action.orEmpty())
    }
}

/** Process-lifetime WiFi listener, independent of the cellular default route. */
object NetworkWatcher {
    const val WIFI_CONNECT_SETTLE_MILLIS = 5_000L
    private var manager: ConnectivityManager? = null
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun isOnWifi(cm: ConnectivityManager): Boolean = try {
        cm.allNetworks.any { network -> cm.getNetworkCapabilities(network)?.let(::isWifi) == true }
    } catch (_: SecurityException) { false }

    private fun isWifi(caps: NetworkCapabilities): Boolean =
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

    @Synchronized
    fun start(context: Context) {
        if (callback != null) return
        val app = context.applicationContext
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val events = Events(app)
        val cb = if (Build.VERSION.SDK_INT >= 31) LocatedCallback(events) else LegacyCallback(events)
        try {
            cm.registerNetworkCallback(NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(), cb)
            manager = cm
            callback = cb
            AuthWorkWiring.progress(app, "自动登录：WiFi 监听已注册")
        } catch (e: RuntimeException) {
            AuthWorkWiring.progress(app, "WiFi 监听注册失败（${e.javaClass.simpleName}）")
        }
    }

    @Synchronized
    fun stop() {
        val cb = callback
        if (cb != null) runCatching { manager?.unregisterNetworkCallback(cb) }
        callback = null
        manager = null
        WifiNetworkNames.clear()
    }

    private class Events(private val context: Context) {
        private val validated = ConcurrentHashMap<Network, Boolean>()
        fun available(network: Network) {
            validated.putIfAbsent(network, false)
            AutoLoginController.requestCheck(context, "wifi-available", reset = true, delayMillis = WIFI_CONNECT_SETTLE_MILLIS)
        }
        fun capabilities(network: Network, caps: NetworkCapabilities) {
            if (!isWifi(caps)) return
            WifiNetworkNames.remember(network, caps)
            val online = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            val previous = validated.put(network, online)
            if (previous == true && !online) {
                AuthWorkWiring.progress(context, "网络检测：目标 WiFi 的互联网验证已失效，安排认证检查")
                AutoLoginController.requestCheck(context, "wifi-validation-lost", reset = true, delayMillis = 1_000L)
            }
        }
        fun lost(network: Network) {
            validated.remove(network)
            WifiNetworkNames.remove(network)
            ActiveWifiSessions.cancelNetwork(network)
            AuthWorkWiring.progress(context, "网络检测：WiFi 连接已断开")
        }
    }

    private class LegacyCallback(private val events: Events) : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = events.available(network)
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = events.capabilities(network, caps)
        override fun onLost(network: Network) = events.lost(network)
    }

    @TargetApi(31)
    private class LocatedCallback(private val events: Events) : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
        override fun onAvailable(network: Network) = events.available(network)
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = events.capabilities(network, caps)
        override fun onLost(network: Network) = events.lost(network)
    }
}
