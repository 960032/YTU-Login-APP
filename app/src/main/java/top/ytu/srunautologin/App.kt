package top.ytu.srunautologin

import android.app.Application
import top.ytu.srunautologin.work.AuthJobs
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
 * 进程被杀后这两条通道会失效，由**开机广播** + **周期任务**（JobScheduler，15 分钟）
 * 兜底 —— 这也是 HyperOS 上「应用被静默杀死」后仍能自愈的关键（另见 ci-report.md 的系统设置提示）。
 *
 * 这里**不做认证**，只排期（避免拖慢应用冷启动；认证由 AuthJobService 在后台线程执行）。
 */
class App : Application() {

    override fun onCreate() {
        super.onCreate()
        try {
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
        } catch (e: Throwable) {
            // 任何初始化异常都不能让应用起不来：记录后继续
            AuthWorkWiring.progress(this, "App.onCreate 初始化失败：${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
