package top.ytu.srunautologin.work

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.app.job.JobWorkItem
import android.content.ComponentName
import android.content.Context

/**
 * ============================ Android 调度层（JobScheduler 方案）============================
 * 本文件引用 Android SDK，**无法在本机离线编译**（本机无 Android SDK），属「未验证」部分。
 * 其中所有可判定的纯逻辑（退避时间、触发条件、重试上限、状态键名）都已抽到
 * [RetryPolicy] / [BackoffScheduler] / [AuthStatusStore] / [AuthWorkCoordinator]，
 * 并在 artifacts/android-ci/build-log.txt 里有真实编译 + 运行记录。
 * ==========================================================================================
 *
 * 为什么选 `JobScheduler + BroadcastReceiver` 而不是 WorkManager（B4 允许二选一）：
 *  1. **零新增第三方依赖**：JobScheduler 是 API 21+ 的系统服务，WorkManager 需要引入
 *     androidx.work:work-runtime-ktx（含 lifecycle/room 等传递依赖），与「零运行时依赖」原则冲突；
 *  2. **本机无法验证依赖能否解析**（无网络），一旦坐标/版本写错，CI 第一步就挂；
 *     系统 API 不存在「拉不到包」的风险；
 *  3. **周期下限同为 15 分钟**：WorkManager 的最小周期 15 分钟与 JobScheduler 的
 *     `setPeriodic(15min)` 一致，收益相同；
 *  4. `setPersisted(true)` 覆盖 WorkManager 的「重启后重新排期」能力，`setRequiredNetworkType`
 *     覆盖 `NetworkType.CONNECTED` 约束，功能上不缺（见 ci-notes.md 的代价对比）。
 */
object AuthJobs {
    /** 一次性认证任务（开机 / 网络变化 / 退避重试共用同一个 jobId，天然去重合并）。 */
    const val JOB_ID_AUTH_ONCE = 0x5A01

    /** 周期保底检查任务。 */
    const val JOB_ID_PERIODIC = 0x5A02

    /** 周期保底间隔：与 WorkManager 的最小周期一致（15 分钟）。 */
    const val PERIODIC_INTERVAL_MINUTES = 15

    /** 周期保底的弹性窗口：留 5 分钟让系统合并唤醒，省电。 */
    const val PERIODIC_FLEX_MINUTES = 5

    /** JobScheduler 的最小延迟单位是毫秒；延迟上限按 API 约束取 14 天以内。 */
    const val MAX_DELAY_MILLIS = 13L * 24 * 60 * 60 * 1000

    fun component(context: Context): ComponentName =
        ComponentName(context.applicationContext, AuthJobService::class.java)
}

/**
 * 调度器：把「触发」翻译成 JobScheduler 排期。
 *
 * 三种触发点（B4）：
 *  1. 开机自启 → [BootCompletedReceiver] → [enqueueAuth]；
 *  2. 网络变化（连上 WiFi）→ [NetworkWatcher] / [NetworkChangeReceiver] → [enqueueAuth]；
 *  3. 周期保底 → [ensurePeriodic]（15 分钟）→ [AuthJobService] 按最小间隔去抖后再认证。
 *
 * 【退避重试】延迟主要由 App 自己的 [BackoffScheduler] 计算（首次 30s、×2、最多 5 次），
 * JobScheduler 的 `setBackoffCriteria` 只作为**兜底**：万一进程被杀、JobService 没机会
 * 调用 `jobFinished`，系统会按指数退避重新投递，避免任务静默消失。
 */
class AndroidAuthScheduler(
    context: Context,
    private val minRetryIntervalMinutes: Long = AuthJobs.PERIODIC_INTERVAL_MINUTES.toLong()
) {
    private val appContext = context.applicationContext
    private val js: JobScheduler? =
        appContext.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler

    /**
     * 排期一次认证。
     *
     * @param delayMillis 延迟毫秒（0 = 尽快）。用 `setMinimumLatency` 实现，
     *        因此**不使用 expedited**（expedited 不允许最小延迟，且 Android 12+ 有配额限制）。
     */
    fun enqueueAuth(delayMillis: Long, reason: String): Boolean {
        val scheduler = js ?: return false
        val safeDelay = delayMillis.coerceIn(0L, AuthJobs.MAX_DELAY_MILLIS)
        val info = JobInfo.Builder(AuthJobs.JOB_ID_AUTH_ONCE, AuthJobs.component(appContext))
            .setMinimumLatency(safeDelay)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .setBackoffCriteria(
                JobInfo.BACKOFF_POLICY_EXPONENTIAL,
                JobInfo.MIN_BACKOFF_MILLIS,
                java.util.concurrent.TimeUnit.MILLISECONDS
            )
            .build()
        return try {
            scheduler.schedule(info)
            recordSchedule(reason, safeDelay)
            true
        } catch (e: SecurityException) {
            // 权限被系统收紧（例如 HyperOS 限制自启动）：静默降级为「未排期」，由周期任务兜底
            recordSchedule("$reason:REJECTED(${e.javaClass.simpleName})", safeDelay)
            false
        }
    }

    /** 排期一次性认证的**替换式**入队（同 jobId 覆盖旧排期，不会堆积）。 */
    fun enqueueAuthReplacing(delayMillis: Long, reason: String): Boolean = enqueueAuth(delayMillis, reason)

    /**
     * 把一次性任务入队到 [AuthJobService] 的 work queue（`enqueue` 的语义是「追加」，
     * 同 jobId 已运行时新 work item 会追加到当前 job，不会丢触发）。
     */
    fun enqueueWorkItem(reason: String): Boolean {
        val scheduler = js ?: return false
        val info = JobInfo.Builder(AuthJobs.JOB_ID_AUTH_ONCE, AuthJobs.component(appContext))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .setBackoffCriteria(
                JobInfo.BACKOFF_POLICY_EXPONENTIAL,
                JobInfo.MIN_BACKOFF_MILLIS,
                java.util.concurrent.TimeUnit.MILLISECONDS
            )
            .build()
        return try {
            val res = scheduler.enqueue(info, JobWorkItem(android.content.Intent().putExtra(EXTRA_REASON, reason)))
            if (res == JobScheduler.RESULT_SUCCESS) {
                recordSchedule(reason, 0L)
                true
            } else {
                false
            }
        } catch (e: SecurityException) {
            recordSchedule("$reason:REJECTED(${e.javaClass.simpleName})", 0L)
            false
        }
    }

    /**
     * 注册周期保底任务（15 分钟一次，带 5 分钟弹性，允许在计费网络/离线时暂缓）。
     * 重复调用是安全的：同 jobId 覆盖，不会产生多个周期任务。
     */
    fun ensurePeriodic(): Boolean {
        val scheduler = js ?: return false
        val info = JobInfo.Builder(AuthJobs.JOB_ID_PERIODIC, AuthJobs.component(appContext))
            .setPeriodic(
                AuthJobs.PERIODIC_INTERVAL_MINUTES * 60_000L,
                AuthJobs.PERIODIC_FLEX_MINUTES * 60_000L
            )
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .build()
        return try {
            scheduler.schedule(info)
            true
        } catch (e: SecurityException) {
            false
        }
    }

    /** 取消全部排期（用户关闭自动登录时使用；本版本 UI 未暴露，保留给后续版本）。 */
    fun cancelAll() {
        js?.cancelAll()
    }

    /**
     * 排期过程的可观测痕迹（纯字符串，写入 SharedPreferences 的调试键）：
     * 真机排障时可在应用信息里看到「最近一次排期原因与延迟」。
     */
    private fun recordSchedule(reason: String, delayMillis: Long) {
        AuthWorkWiring.keyValueStore(appContext)
            .putString(AuthStatusKeys.ATTEMPT_STATE + ".last_schedule", "$reason|$delayMillis")
    }

    companion object {
        const val EXTRA_REASON = "reason"

        /** 周期任务去抖间隔（秒）：周期保底唤醒时，距上次尝试不足该值则不重复请求。 */
        fun minRetryIntervalSecondsFor(periodicIntervalMinutes: Long): Long =
            periodicIntervalMinutes.coerceAtLeast(1L) * 60L / 2L    }
}
