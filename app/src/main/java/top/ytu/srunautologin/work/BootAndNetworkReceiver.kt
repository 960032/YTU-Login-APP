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
 * 【触发点 1/3：开机自启】`android.intent.action.BOOT_COMPLETED`。
 *
 * 注意（Android 7+ 隐式广播限制）：
 *  - `BOOT_COMPLETED`、`LOCKED_BOOT_COMPLETED`、`MY_PACKAGE_REPLACED` 属于**豁免清单**，
 *    可以在 manifest 静态注册；
 *  - `CONNECTIVITY_ACTION` 在 Android 7.0（API 24）起**被移出豁免清单**，静态注册收不到，
 *    必须动态注册 [NetworkChangeReceiver] 或改用 `NetworkCallback` —— 本实现两条都做了：
 *      * 动态注册 [NetworkChangeReceiver]（`registerReceiver` 的 RECEIVER_NOT_EXPORTED）；
 *      * [NetworkWatcher] 用 `ConnectivityManager.registerNetworkCallback` 监听 WiFi 可用性。
 *  - 因此**不依赖** manifest 里的 CONNECTIVITY_ACTION。
 *
 * 【A1 冷启动时序】开机那一刻 WiFi 往往还没连上，所以这里只负责「排期」，
 * 真正的「WiFi 没就绪 → 短延迟重试」由 [AuthWorkCoordinator] + [BackoffScheduler] 处理。
 */
class BootCompletedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        val ctx = context?.applicationContext ?: return
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        AuthWorkWiring.progress(ctx, "trigger: $action")

        // 【C4 覆盖检查：入口 3/7】开机自启 —— 停用时直接返回，不排任何后台任务。
        if (!MorningAuthRuntime.isEnabled(ctx)) {
            AuthWorkWiring.progress(ctx, "trigger: $action 但自动登录已停用 → 直接返回")
            return
        }

        // 周期保底先注册（15 分钟），再排一次尽快执行的认证：
        // 开机后用户可能已经连上校园网，也可能还没连上——都交给 AuthFlow 判断。
        AuthWorkWiring.scheduler(ctx).ensurePeriodic()
        AuthWorkWiring.scheduler(ctx).enqueueAuth(
            delayMillis = BOOT_INITIAL_DELAY_MILLIS,
            reason = "boot"
        )
    }

    companion object {
        /**
         * 开机后首个认证尝试的短延迟：给系统留出「WiFi 自动连接」的时间窗口。
         * 30 秒后仍没连上也不判失败——AuthFlow 会返回 E_SKIP_NO_SSID，
         * 由退避策略安排下一次短延迟复检（A1 冷启动时序）。
         */
        const val BOOT_INITIAL_DELAY_MILLIS = 30_000L
    }
}

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

        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        if (!NetworkWatcher.isOnWifi(cm)) {
            AuthWorkWiring.progress(ctx, "trigger: CONNECTIVITY_ACTION（非 WiFi，忽略）")
            return
        }
        // 【C4 覆盖检查：入口 4/7】WiFi 连接变化（动态广播）—— 停用时直接返回。
        if (!MorningAuthRuntime.isEnabled(ctx)) {
            AuthWorkWiring.progress(ctx, "trigger: CONNECTIVITY_ACTION 但自动登录已停用 → 直接返回")
            return
        }
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
 * 周期任务 + 开机广播 + 下一次打开应用兜底。
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
                // 【C4 覆盖检查：入口 5/7】NetworkCallback —— 停用时直接返回。
                if (!MorningAuthRuntime.isEnabled(ctx)) {
                    AuthWorkWiring.progress(ctx, "trigger: NetworkCallback($what) 但自动登录已停用 → 直接返回")
                    return
                }
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
