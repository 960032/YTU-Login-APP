package top.ytu.srunautologin.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import top.ytu.srunautologin.auth.ConnectionFactory
import java.net.URL
import java.net.URLConnection

/**
 * ============================ Android 边界层（本机无 Android 运行时，未离线验证） ============================
 *
 * 【netfix1 任务 A/C 段】显式绑定 WiFi 网络的连接工厂。
 *
 * **为什么要它**：`URL(url).openConnection()` 只走**系统默认网络**。当手机同时具备 WiFi（校园网，未认证）
 * 与移动数据时，Android 判定该 WiFi「无互联网（captive portal）」→ 默认网络 = 移动数据；而校园网门户是
 * **内网地址**（真机日志：202.194.116.116:80），在移动数据上不可达 → connect 超时
 * （真机日志：15s SocketTimeoutException；同一地址偶尔 33ms 成功 = 那一刻默认网络恰好是 WiFi）。
 *
 * **本类只做一件事**：从 [ConnectivityManager.allNetworks] 里挑出 **WiFi 传输**的 [Network]，
 * 用 [Network.openConnection]（API 21+）在该网络上发起连接 —— 与浏览器打开门户时的选网行为一致。
 * 不改任何系统设置、不需要任何权限（`getNetworkCapabilities` 无需权限；本类**不读 SSID**）。
 *
 * 【诊断】[networkDescription] 供上层把「默认网络类型 + 是否找到可绑定的 WiFi」写进日志
 * （网络类型的判断在 Android 边界层完成，纯逻辑层只收到字符串）。
 * =========================================================================================================
 */
class WifiFirstConnectionFactory(context: Context) : ConnectionFactory {

    /**
     * 只持有 **applicationContext**：本对象会被塞进 `auth.HttpUrlConnectionEngine` 并由 authFlow 长期持有，
     * 持有 Activity 会造成泄漏。
     */
    private val appContext: Context = context.applicationContext

    private val cm: ConnectivityManager? = try {
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    } catch (t: Throwable) {
        null
    }

    /**
     * 在「WiFi 网络」上打开连接。
     *
     * **绝不抛异常**：任何异常（无 ConnectivityManager、无 WiFi 网络、系统实现差异、安全异常）
     * 一律返回 null → 由 `HttpUrlConnectionEngine` 回退到系统默认网络。
     * 修复不允许把「原来的超时」变成「崩溃」。
     */
    override fun open(url: URL): URLConnection? = try {
        selectedWifiNetwork()?.openConnection(url)
    } catch (t: Throwable) {
        null
    }

    /**
     * 选取 WiFi 网络：
     *  1. 优先**已验证（validated，能上网）**的 WiFi；
     *  2. 都未验证时**仍然返回 WiFi 网络** —— 校园网「已连上但未认证」正是这种状态，
     *     而门户地址就在这张网内，必须绑到它上面；
     *  3. WiFi 一个都没有时，兜底看 `activeNetwork` 本身是不是 WiFi（个别系统实现下 allNetworks 会被裁剪）。
     */
    fun selectedWifiNetwork(): Network? {
        val manager = cm ?: return null
        val all: Array<Network> = try {
            manager.allNetworks
        } catch (t: Throwable) {
            emptyArray()
        }
        val wifi = all.filter { isWifi(manager, it) }
        return wifi.firstOrNull { isValidated(manager, it) }
            ?: wifi.firstOrNull()
            ?: activeNetwork(manager)?.takeIf { isWifi(manager, it) }
    }

    /**
     * 诊断字符串（一行，**不含 SSID、不含任何凭据/账号**）：
     * 默认网络类型（WiFi / 移动数据 / 以太网 / 未知）+ 是否已验证 + 本次是否能绑定到 WiFi。
     */
    fun networkDescription(): String {
        val manager = cm ?: return "网络=未知(无 ConnectivityManager)"
        val active = activeNetwork(manager)
        val caps = if (active == null) {
            null
        } else {
            try {
                manager.getNetworkCapabilities(active)
            } catch (t: Throwable) {
                null
            }
        }
        val validated = if (active != null && isValidated(manager, active)) "已验证" else "未验证"
        val bound = if (selectedWifiNetwork() == null) "未找到WiFi网络(走系统默认)" else "已绑定WiFi网络"
        return "默认网络=${transportName(caps)}($validated) $bound"
    }

    /** `activeNetwork` 需要 API 23；低版本返回 null（工厂的选网仍可通过 allNetworks 完成）。 */
    private fun activeNetwork(manager: ConnectivityManager): Network? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                manager.activeNetwork
            } catch (t: Throwable) {
                null
            }
        } else {
            null
        }

    private fun isWifi(manager: ConnectivityManager, net: Network): Boolean = try {
        manager.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    } catch (t: Throwable) {
        false
    }

    /** 是否「已验证可上网」（API 23+ 才有该能力标志；低版本一律 false，不影响选网）。 */
    private fun isValidated(manager: ConnectivityManager, net: Network): Boolean = try {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            false
        } else {
            manager.getNetworkCapabilities(net)
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        }
    } catch (t: Throwable) {
        false
    }

    private fun transportName(caps: NetworkCapabilities?): String = when {
        caps == null -> "未知"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "移动数据"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "以太网"
        else -> "未知"
    }
}
