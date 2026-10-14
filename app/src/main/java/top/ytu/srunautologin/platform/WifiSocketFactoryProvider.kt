package top.ytu.srunautologin.platform

import android.content.Context
import top.ytu.srunautologin.auth.SocketFactoryProvider
import java.net.Socket

/**
 * ============================ Android 边界层（本机无 Android 运行时，未离线验证） ============================
 *
 * 【onlinefix1 任务 B 段】在**选定的 WiFi 网络**上创建 Socket 的实现。
 *
 * **为什么需要它**：上一个修复（netfix1）的 [WifiFirstConnectionFactory] 只覆盖了 **HTTP 引擎**；
 * 本机 IP 探测（`auth.SocketLocalIpProbe`）用的是裸 `Socket()` → 走**系统默认网络**。校园网未认证时
 * Android 判定该 WiFi「无互联网（captive portal）」→ 默认网络 = 移动数据 → 探测到的 `localAddress`
 * 不是 WiFi 侧地址（或连不上门户）→ 传给门户的 `ip` 参数不准。
 *
 * **做法**：复用 [WifiFirstConnectionFactory.selectedWifiNetwork] 的选网口径（优先已验证 WiFi，
 * 否则任意 WiFi，否则 activeNetwork 若是 WiFi），再调 `Network.getSocketFactory().createSocket()`
 * —— 与 [WifiFirstConnectionFactory] 用 `Network.openConnection(url)` 是同一套「绑网」语义。
 *
 * **permission**：本类**不需要任何权限**。`getNetworkCapabilities` / `allNetworks` 无需权限；
 * `Network.getSocketFactory()` 属于 ConnectivityManager 的公开 API（API 21+），
 * 也**不读 SSID**、不改任何系统设置。
 *
 * **绝不抛异常**：无 ConnectivityManager / 无 WiFi 网络 / 系统实现差异 / 安全异常
 * 一律返回 null → `SocketLocalIpProbe` 回退到旧行为（系统默认网络）。
 * =========================================================================================================
 */
class WifiSocketFactoryProvider(context: Context) : SocketFactoryProvider {

    /** 只持 **applicationContext**：本对象会被 `auth.SocketLocalIpProbe` 长期持有（持 Activity 会泄漏）。 */
    private val appContext: Context = context.applicationContext

    /** 选网口径与 HTTP 侧**完全一致**（复用同一个类，避免两份选网逻辑漂移）。 */
    private val picker = WifiFirstConnectionFactory(appContext)

    override fun createSocket(host: String, port: Int, timeoutMs: Int): Socket? = try {
        val network = picker.selectedWifiNetwork()
        if (network == null) {
            // 拿不到 WiFi 网络（例如只有移动数据 / 系统裁剪 allNetworks）→ null = 走旧行为
            null
        } else {
            val socket = network.socketFactory.createSocket()
            // `Socket.connect(host, port, timeout)` 语义与 `Network.getSocketFactory().createSocket(host, port)`
            // 相同（在本网络上完成 DNS 与 TCP），但**超时可控**，与改造前的探测口径一致。
            if (timeoutMs > 0) socket.soTimeout = timeoutMs
            socket
        }
    } catch (t: Throwable) {
        // 修复不允许把「IP 不准」变成「探测崩溃」：任何异常都回退旧行为
        null
    }
}
