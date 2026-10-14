package top.ytu.srunautologin

import android.app.Application
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.work.AuthJobs
import top.ytu.srunautologin.work.AutoLoginSwitch
import top.ytu.srunautologin.work.MorningAuthForegroundService
import top.ytu.srunautologin.work.startAutoLoginNotification
import top.ytu.srunautologin.work.AuthWorkWiring
import top.ytu.srunautologin.work.NetworkChangeReceiver
import top.ytu.srunautologin.work.NetworkWatcher

/**
 * ============================ Android 边界层（未验证部分）============================
 * 引用 Android SDK，本机无 Android SDK 无法离线编译。
 *
 * 应用入口：注册后台认证的**运行期触发通道**（B4 触发点 2）。
 *  - 动态注册 `CONNECTIVITY_ACTION`（Android 7+ 隐式广播限制下静态注册收不到）；
 *  - 注册 `ConnectivityManager.NetworkCallback`（比广播更可靠）。
 *
 * 【removemorning1（用户要求）】开机广播触发通道**已关闭**（manifest 里的接收者与权限均已删除），
 * 进程被杀后由 **周期任务**（JobScheduler，15 分钟）兜底 —— 这也是 HyperOS 上「应用被静默杀死」
 * 后仍能自愈的关键（另见 ci-report.md 的系统设置提示）。
 * 同时按用户要求**取消每天早上 6:00 的定时任务/闹钟与其提示文本**：原先在 onCreate 里的
 * 「启停开关」判断与「早上常驻通知前台服务」启动调用一并移除；
 * 网络变化 + 周期保底两条通道**按用户要求保留**，且不再被任何隐藏开关挡住。
 *
 * 这里**不做认证**，只排期（避免拖慢应用冷启动；认证由 AuthJobService 在后台线程执行）。
 */
class App : Application() {

    override fun onCreate() {
        super.onCreate()
        try {
            // restoretoggle1（用户要求「恢复控制开关 + 默认启用」）：闸门**恢复**，但语义与 removemorning1
            // 当年的情形已不同——开关的界面入口（按钮 + 绿/红状态文本）本次一并恢复，且默认是**启用**
            // （AutoLoginSwitch.DEFAULT_ENABLED = true），因此保留闸门不再有「默认配置下后台全失效」的风险：
            //   · 启用（默认）→ 下面三条通道照旧全部注册；
            //   · 停用（用户主动点击）→ 直接返回：不注册监听、不排期、不认证（并落一条日志）。
            // 【dozefix1 任务 A 段】定期保底闹钟（AlarmManager.setExactAndAllowWhileIdle，**穿透 Doze**）：
            // 幂等确保已排上；**开关停用时它自己会取消且不重排**（开关判断在方法内部）。
            // 刻意放在下面闸门判断**之前**：这样「停用 → App.onCreate 直接 return」这条路径
            // 也会先完成「取消闹钟」，不会留下一个仍在跑的旧闹钟。
            runCatching { top.ytu.srunautologin.work.MorningAuthRuntime.ensurePeriodicCheck(this) }

            val switchKv = SrunStorage.keyValueStore(this)
            AutoLoginSwitch.gateReason(switchKv, "App.onCreate")?.let { reason ->
                AuthWorkWiring.progress(this, reason)
                runCatching {
                    top.ytu.srunautologin.log.AppLog.record(switchKv, "调度：$reason")
                }
                return
            }

            // 触发点 2：WiFi 连接变化（两条通道都注册）
            NetworkChangeReceiver.register(this)
            NetworkWatcher.start(this)

            // 触发点 3：周期保底（15 分钟）+ 本进程启动时补一次
            AuthWorkWiring.onTrigger(
                context = this,
                reason = "app-start",
                initialDelayMillis = 0L
            )
            AuthWorkWiring.progress(
                this,
                "App.onCreate: 已注册网络监听 + 周期保底（间隔 ${AuthJobs.PERIODIC_INTERVAL_MINUTES} 分钟）"
            )

            // restoretoggle1：进程重建/App 启动时按开关状态**恢复常驻通知**（否则重启 App 后通知不见了）。
            // 只在「已启用」时恢复（正面判断）；前台服务启动受 Android 12+ 后台启动限制，
            // 是否真的在后台由 MorningAuthForegroundService.startIfAllowed() 判定（内部 try/catch 兜住）。
            resumeForegroundNotificationIfEnabled()

            // restoretoggle1：应用被覆盖安装/升级（ACTION_MY_PACKAGE_REPLACED）后本进程会被重建，
            // 而系统在升级时会杀掉进程并移除前台状态 —— 这是「升级后通知不见了」最可能的真机场景。
            // 该广播**不是开机广播**（BOOT_COMPLETED 仍保持删除状态），只在本应用被替换时由系统投递。
            // 启动前台服务仍可能被系统拒绝（后台启动限制）→ 同样走 startIfAllowed() 的 try/catch，绝不崩溃。
            try {
                registerReceiver(
                    packageReplacedReceiver,
                    android.content.IntentFilter(android.content.Intent.ACTION_MY_PACKAGE_REPLACED)
                )
            } catch (t: Throwable) {
                AuthWorkWiring.progress(this, "App.onCreate 注册升级广播失败（已忽略）：${t.javaClass.simpleName}")
            }
        } catch (e: Throwable) {
            // 任何初始化异常都不能让应用起不来：记录后继续
            AuthWorkWiring.progress(this, "App.onCreate 初始化失败：${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * 升级/覆盖安装后的恢复路径。**只做一件事**：若开关为「已启用」就请求启动常驻通知前台服务。
     * 前台服务启动限制（Android 12+ 后台启动抛 ForegroundServiceStartNotAllowedException、
     * Android 14+ 还要求类型与权限匹配）全部由 startIfAllowed() 兜住，这里不再重复 try/catch。
     */
    private val packageReplacedReceiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(context: android.content.Context?, intent: android.content.Intent?) {
            if (intent?.action != android.content.Intent.ACTION_MY_PACKAGE_REPLACED) return
            AuthWorkWiring.progress(
                applicationContext,
                "升级完成（ACTION_MY_PACKAGE_REPLACED）→ 按开关状态恢复常驻通知"
            )
            resumeForegroundNotificationIfEnabled()
        }
    }

    /** 「已启用」时确保常驻通知在运行；停用时**什么都不做**（通知在用户停用时已停止）。 */
    private fun resumeForegroundNotificationIfEnabled() {
        val kv = SrunStorage.keyValueStore(this)
        if (AutoLoginSwitch.isEnabled(kv)) {
            startAutoLoginNotification()
        } else {
            AuthWorkWiring.progress(this, "自动登录已停用，跳过：App.onCreate 恢复常驻通知")
        }
    }
}
