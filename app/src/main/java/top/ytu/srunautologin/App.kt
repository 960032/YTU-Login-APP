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
            // removemorning1：原「启停开关停用 → 一个后台入口都不注册/不排期」的闸门已移除。
            // 依据：该开关的唯一界面入口（morning1 的启停按钮）按用户要求删除，开关默认值是停用
            // （MorningStateStore.DEFAULT_ENABLED = false）；保留闸门会让「网络变化 + 周期保底」
            // 这两条**必须保留**的通道在默认配置下全部失效（等于取消全部后台登录）。

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

            // removemorning1：原先这里还会「进程重建时恢复早上任务的常驻通知」——
            // 该前台服务随早上任务一并移除，这段恢复逻辑整体删除。
        } catch (e: Throwable) {
            // 任何初始化异常都不能让应用起不来：记录后继续
            AuthWorkWiring.progress(this, "App.onCreate 初始化失败：${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
