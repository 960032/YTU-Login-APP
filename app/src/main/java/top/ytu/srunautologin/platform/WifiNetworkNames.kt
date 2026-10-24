package top.ytu.srunautologin.platform

import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.os.Build
import java.util.concurrent.ConcurrentHashMap

/** Location-aware callbacks can supply identities redacted from synchronous capability reads. */
object WifiNetworkNames {
    private val names = ConcurrentHashMap<Network, String>()
    fun remember(network: Network, capabilities: NetworkCapabilities) {
        if (Build.VERSION.SDK_INT < 29) return
        val raw = (capabilities.transportInfo as? WifiInfo)?.ssid ?: return
        val ssid = raw.removeSurrounding("\"")
        if (ssid.isNotBlank() && !ssid.equals("<unknown ssid>", true)) names[network] = ssid
    }
    fun get(network: Network): String? = names[network]
    fun remove(network: Network) { names.remove(network) }
    fun clear() { names.clear() }
}
