package top.ytu.srunautologin.work

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build

/**
 * ============================ Android 边界层（未验证部分）============================
 * 引用 Android SDK，本机无 SDK 无法离线编译。
 * =====================================================================================
 *
 * 【removemorning1（用户要求「关闭开机广播的触发通道」）】
 *  - 「触发点 1/3：开机自启」**已整块删除**：静态注册的开机广播接收者类、`BOOT_COMPLETED` /
 *    `LOCKED_BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` 三个 action、以及 `RECEIVE_BOOT_COMPLETED`
 *    权限全部移除；本文件只剩下面这条「网络变化」触发通道。
 *
 * 【触发点 2/3：网络变化】（**保留**能力，未受本任务影响）
 *  - `CONNECTIVITY_ACTION` 在 Android 7.0（API 24）起**被移出隐式广播豁免清单**，静态注册收不到，
 *    必须动态注册 [NetworkChangeReceiver] 或改用 `NetworkCallback` —— 本实现两条都做了：
 *     * 动态注册 [NetworkChangeReceiver]（`registerReceiver` 的 RECEIVER_NOT_EXPORTED）；
 *     * [NetworkWatcher] 用 `ConnectivityManager.registerNetworkCallback` 监听 WiFi 可用性。
 *  - 因此**不依赖** manifest 里的 CONNECTIVITY_ACTION。
 *
 * 【A1 冷启动时序】连上 WiFi 那一刻门户往往还没就绪，所以这里只负责「排期」，
 * 真正的「WiFi 没就绪 → 短延迟重试」由 [AuthWorkCoordinator] + [BackoffScheduler] 处理。
 */
// removemorning1：原「开机自启接收者」类（整个类，含 companion object 里的
// BOOT_INITIAL_DELAY_MILLIS = 30_000L 常量）已按用户要求删除。全工程 grep 确认：
// 该常量与类名在其它文件中**没有任何代码引用**（仅 work/AuthScheduler.kt 的
// 注释里还剩一处说明性文字，属文档残留，见 fix-report.md 的 A 段与「未改动项」）。

/**
 * 【触发点 2/3：网络变化】动态注册的 `CONNECTIVITY_ACTION` 接收者。
 *
 * 只在**连上 WiFi** 时才排期认证（移动数据变化不触发，避免无谓唤醒）；
 * 是否真的发请求仍由 AuthFlow 的 B8 判定。
 */
class NetworkChangeReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        val ctx = context?.applicationContext ?: return
        if (intent?.action != ConnectivityManager.CONNECTIVITY_ACTION) return

        // 【logfix1 任务 B 段·网络变化埋点】用户要求记录「检测网络是否符合登陆要求」全过程，
        // 起点就是「检测到网络变化」。这条日志与既有 progress 并行写，互不替代。
        runCatching {
            top.ytu.srunautologin.log.AppLog.record(
                top.ytu.srunautologin.platform.SrunStorage.keyValueStore(ctx),
                "调度：检测到网络变化（CONNECTIVITY_ACTION）"
            )
        }

        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        if (!NetworkWatcher.isOnWifi(cm)) {
            AuthWorkWiring.progress(ctx, "trigger: CONNECTIVITY_ACTION（非 WiFi，忽略）")
            return
        }
        // removemorning1：原「启停开关停用 → 直接返回」的闸门已移除。
        // 依据：开关唯一的界面入口（morning1 的启停按钮）按用户要求删除；而开关默认值是
        // 停用（MorningStateStore.DEFAULT_ENABLED = false），保留闸门会让这两条**必须保留**
        // 的网络变化通道在默认配置下全部失效，等于变相「取消全部后台登录」。
        AuthWorkWiring.progress(ctx, "trigger: CONNECTIVITY_ACTION（已连上 WiFi）")
        AuthWorkWiring.scheduler(ctx).enqueueAuth(
            delayMillis = WIFI_CONNECT_SETTLE_MILLIS,
            reason = "network"
        )
    }

    companion object {
        /**
         * 连上 WiFi 后先等 5 秒再认证：
         * 刚连上时 DHCP/门户重定向可能还没完成，过早请求会拿到 E_NETWORK 而白白消耗一次退避次数。
         */
        const val WIFI_CONNECT_SETTLE_MILLIS = 5_000L

        /** 单例接收者（同一个实例才能保证动态注册/注销配对，不会重复触发）。 */
        private val INSTANCE = NetworkChangeReceiver()

        /** 动态注册用：只关心连接变化（RECEIVER_NOT_EXPORTED，API 33+ 必需标志）。 */
        fun register(context: Context) {
            val filter = android.content.IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
            try {
                if (Build.VERSION.SDK_INT >= 33) {
                    context.registerReceiver(INSTANCE, filter, Context.RECEIVER_NOT_EXPORTED)
                } else {
                    @Suppress("UnspecifiedRegisterReceiverFlag")
                    context.registerReceiver(INSTANCE, filter)
                }
            } catch (e: SecurityException) {
                AuthWorkWiring.progress(context, "CONNECTIVITY_ACTION 动态注册被拒：${e.javaClass.simpleName}")
            }
        }
    }
}

/**
 * 【触发点 2/3 的第二个通道：NetworkCallback】
 *
 * 比 `CONNECTIVITY_ACTION` 更可靠（不会被隐式广播限制影响），
 * 在「默认网络变成 WiFi」或「WiFi 网络的能力发生变化」时排期一次认证。
 * 注册在 Application.onCreate（应用进程存活期间有效）——进程被杀后由
 * 周期任务（15 分钟 JobScheduler，**保留**）+ 下一次打开应用兜底
 * （removemorning1：开机广播已按用户要求关闭，不再作为兜底通道）。
 */
object NetworkWatcher {

    private var registered = false

    /** 当前默认网络是否为已连接的 WiFi（`TRANSPORT_WIFI` 且已上网/已连接）。 */
    fun isOnWifi(cm: ConnectivityManager): Boolean {
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    /** 注册监听；重复调用安全。失败只记录、不抛异常（权限被拒时静默降级）。 */
    fun start(context: Context) {
        if (registered) return
        val ctx = context.applicationContext
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            private fun onWifiEvent(what: String) {
                // removemorning1：启停开关闸门已移除（理由同 NetworkChangeReceiver.onReceive）。
                AuthWorkWiring.progress(ctx, "trigger: NetworkCallback($what)")
                AuthWorkWiring.scheduler(ctx).enqueueAuth(
                    delayMillis = NetworkChangeReceiver.WIFI_CONNECT_SETTLE_MILLIS,
                    reason = "network-$what"
                )
            }

            override fun onAvailable(network: Network) = onWifiEvent("available")

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    onWifiEvent("validated")
                }
            }
        }
        try {
            cm.registerNetworkCallback(request, callback)
            registered = true
        } catch (e: SecurityException) {
            AuthWorkWiring.progress(ctx, "NetworkCallback 注册被拒：${e.javaClass.simpleName}")
        }
    }
}

/** 目前无需额外的 IntentFilter 包装：动态注册直接在 [NetworkChangeReceiver.register] 中完成。 */
