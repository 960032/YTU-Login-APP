package top.ytu.srunautologin.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.net.URLConnection
import java.util.concurrent.ConcurrentHashMap
import top.ytu.srunautologin.auth.ConnectionFactory
import top.ytu.srunautologin.auth.NetworkBindingException

/** Captures one identifiable WiFi network; no request ever falls back to another transport. */
class WifiFirstConnectionFactory(context: Context, targetSsid: String? = null) : ConnectionFactory {
    private val appContext = context.applicationContext
    private val manager = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        ?: throw NetworkBindingException("无法读取网络状态")
    private val expectedSsid = targetSsid?.takeIf { it.isNotEmpty() } ?: currentLegacySsid()
        ?: throw NetworkBindingException("无法识别目标 WiFi，请检查 WiFi 和位置信息权限")
    private val pinned: Network = capture()
    private val connections = ConcurrentHashMap.newKeySet<HttpURLConnection>()
    private val sockets = ConcurrentHashMap.newKeySet<java.net.Socket>()
    @Volatile private var closed = false

    private fun capture(): Network {
        val candidates = try {
            manager.allNetworks.filter { network -> manager.getNetworkCapabilities(network)?.let(::isWifi) == true }
        } catch (_: SecurityException) { emptyList() }
        val matches = candidates.filter { ssidOf(it) == expectedSsid }
        if (matches.size == 1) return matches.single()
        if (matches.isEmpty() && candidates.size == 1 && currentLegacySsid() == expectedSsid) {
            return candidates.single()
        }
        throw NetworkBindingException("目标 WiFi 不可用或存在多个无法区分的连接")
    }

    fun requireNetwork(): Network {
        if (closed) throw NetworkBindingException("本轮认证已取消")
        val capabilities = try { manager.getNetworkCapabilities(pinned) }
        catch (_: SecurityException) { null }
        if (capabilities == null || !isWifi(capabilities)) throw NetworkBindingException()
        val current = ssidOf(pinned) ?: currentLegacySsid()
        if (current != expectedSsid) throw NetworkBindingException("WiFi 已变化或名称不可用，本轮认证已停止")
        return pinned
    }

    fun selectedWifiNetwork(): Network? = try { requireNetwork() }
    catch (_: NetworkBindingException) { null }

    fun isBoundTo(network: Network): Boolean = pinned == network

    override fun open(url: URL): URLConnection {
        val connection = requireNetwork().openConnection(url, Proxy.NO_PROXY)
        if (connection is HttpURLConnection) {
            connections.add(connection)
            if (closed) { connection.disconnect(); throw NetworkBindingException() }
        }
        return connection
    }

    fun trackSocket(socket: java.net.Socket) {
        sockets.add(socket)
        if (closed) { socket.close(); throw NetworkBindingException() }
    }

    fun close() {
        closed = true
        connections.forEach { runCatching { it.disconnect() } }
        connections.clear()
        sockets.forEach { runCatching { it.close() } }
        sockets.clear()
    }

    fun networkDescription(): String = "认证网络=WiFi network=$pinned state=${if (closed) "closed" else "pinned"}"

    private fun isWifi(capabilities: NetworkCapabilities): Boolean =
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

    private fun ssidOf(network: Network): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            normalizeSsid((manager.getNetworkCapabilities(network)?.transportInfo as? WifiInfo)?.ssid)
                ?: WifiNetworkNames.get(network)
        } else WifiNetworkNames.get(network)
    } catch (_: SecurityException) { null }

    @Suppress("DEPRECATION")
    private fun currentLegacySsid(): String? = try {
        val wifi = appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        normalizeSsid(wifi?.connectionInfo?.ssid)
    } catch (_: SecurityException) { null }

    private fun normalizeSsid(raw: String?): String? = raw?.removeSurrounding("\"")
        ?.takeUnless { it.isBlank() || it.equals("<unknown ssid>", ignoreCase = true) || it == "0x" }
}
