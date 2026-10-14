package top.ytu.srunautologin.work

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.app.job.JobWorkItem
import android.content.ComponentName
import android.content.Context
import top.ytu.srunautologin.log.AppLog

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
     *
     * 【persistfix1 加固】`setPersisted(true)` 要求持有 `RECEIVE_BOOT_COMPLETED`
     * （见 AndroidManifest 的防误删告警块）。权限一旦缺失，`schedule()` 抛的是
     * **IllegalArgumentException**（不是 SecurityException），旧代码只捕 SecurityException →
     * 异常穿透到系统回调（NetworkWatcher 的 HandlerThread）→ **进程崩溃**。
     * 现在：捕 RuntimeException + 记日志 + 降级为 setPersisted(false) 重试一次。
     */
    fun enqueueAuth(delayMillis: Long, reason: String): Boolean {
        val scheduler = js ?: return false
        val safeDelay = delayMillis.coerceIn(0L, AuthJobs.MAX_DELAY_MILLIS)
        return try {
            scheduler.schedule(buildAuthInfo(safeDelay, persisted = true))
            recordSchedule(reason, safeDelay)
            true
        } catch (e: RuntimeException) {
            handleScheduleFailure(e, reason, reason) {
                scheduler.schedule(buildAuthInfo(safeDelay, persisted = false))
                recordSchedule("$reason:UNPERSISTED", safeDelay)
                true
            }
        }
    }

    /** 构造一次性认证的 [JobInfo]；[persisted] = 是否要求「排期跨重启保留」（需 RECEIVE_BOOT_COMPLETED）。 */
    private fun buildAuthInfo(delayMillis: Long, persisted: Boolean): JobInfo =
        JobInfo.Builder(AuthJobs.JOB_ID_AUTH_ONCE, AuthJobs.component(appContext))
            .setMinimumLatency(delayMillis)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(persisted)
            .setBackoffCriteria(
                JobInfo.DEFAULT_INITIAL_BACKOFF_MILLIS,
                JobInfo.BACKOFF_POLICY_EXPONENTIAL
            )
            .build()


    /** 排期一次性认证的**替换式**入队（同 jobId 覆盖旧排期，不会堆积）。 */
    fun enqueueAuthReplacing(delayMillis: Long, reason: String): Boolean = enqueueAuth(delayMillis, reason)

    /**
     * 把一次性任务入队到 [AuthJobService] 的 work queue（`enqueue` 的语义是「追加」，
     * 同 jobId 已运行时新 work item 会追加到当前 job，不会丢触发）。
     */
    fun enqueueWorkItem(reason: String): Boolean {
        val scheduler = js ?: return false
        val persistedInfo = JobInfo.Builder(AuthJobs.JOB_ID_AUTH_ONCE, AuthJobs.component(appContext))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .setBackoffCriteria(
                JobInfo.DEFAULT_INITIAL_BACKOFF_MILLIS,
                JobInfo.BACKOFF_POLICY_EXPONENTIAL
            )
            .build()
        return try {
            val res = scheduler.enqueue(persistedInfo, JobWorkItem(android.content.Intent().putExtra(EXTRA_REASON, reason)))
            if (res == JobScheduler.RESULT_SUCCESS) {
                recordSchedule(reason, 0L)
                true
            } else {
                false
            }
        } catch (e: RuntimeException) {
            // persistfix1：同 enqueueAuth —— 权限缺失时 schedule/enqueue 抛 IllegalArgumentException（非 SecurityException）。
            // 降级：去掉 setPersisted(true) 重试一次，绝不把异常放回系统回调。
            handleScheduleFailure(e, "work_item:$reason", reason) { scheduler.schedule(buildAuthInfo(0L, persisted = false)).let { recordSchedule("$reason:UNPERSISTED", 0L); true } }
        }
    }


    /**
     * 注册周期保底任务（15 分钟一次，带 5 分钟弹性，允许在计费网络/离线时暂缓）。
     * 重复调用是安全的：同 jobId 覆盖，不会产生多个周期任务。
     */
    fun ensurePeriodic(): Boolean {
        val scheduler = js ?: return false
        return try {
            scheduler.schedule(buildPeriodicInfo(persisted = true))
            true
        } catch (e: RuntimeException) {
            // persistfix1：权限缺失 → IllegalArgumentException；降级为不持久化的周期排期（功能仍可用）。
            handleScheduleFailure(e, "periodic", "periodic") {
                scheduler.schedule(buildPeriodicInfo(persisted = false))
                true
            }
        }
    }

    /** 构造周期保底任务的 [JobInfo]；[persisted] 含义同 [buildAuthInfo]。 */
    private fun buildPeriodicInfo(persisted: Boolean): JobInfo =
        JobInfo.Builder(AuthJobs.JOB_ID_PERIODIC, AuthJobs.component(appContext))
            .setPeriodic(
                AuthJobs.PERIODIC_INTERVAL_MINUTES * 60_000L,
                AuthJobs.PERIODIC_FLEX_MINUTES * 60_000L
            )
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(persisted)
            .build()

    /**
     * persistfix1 统一的排期失败处置：**先记日志（绝不静默），再尝试降级 [fallback]**。
     *
     * 为什么不区分异常类型：`schedule()` 可能抛 SecurityException（权限被 OEM 收紧）、
     * IllegalArgumentException（setPersisted 缺 RECEIVE_BOOT_COMPLETED，**本次真机崩溃**）
     * 或 IllegalStateException（JobService 未声明等）。它们都**起源于系统回调线程**，
     * 穿透即进程崩溃 → 一律兜住。
     *
     * @param tag 日志标签（who 失败）；[reason] 业务原因；[fallback] 降级动作（返回是否成功）。
     */
    private fun handleScheduleFailure(e: RuntimeException, tag: String, reason: String, fallback: () -> Boolean): Boolean {
        // 1) 记日志：两条通道 —— AuthWorkWiring.progress（进度键，真机在应用信息里可读）
        //    与 AppLog.record（界面「日志」窗口可见）。AppLog 内部已 runCatching + 脱敏，不会抛。
        val detail = "$tag 排期被系统拒绝：${e.javaClass.simpleName}: ${e.message}"
        recordSchedule("$reason:REJECTED(${e.javaClass.simpleName})", -1L)
        runCatching { AuthWorkWiring.progress(appContext, detail) }
        runCatching { AppLog.record(AuthWorkWiring.keyValueStore(appContext), detail) }
        // 2) 降级：去掉 setPersisted(true) 重试一次（权限被误删时功能仍可用，只是重启后需重开 App）。
        return runCatching { fallback() }
            .onSuccess {
                runCatching { AuthWorkWiring.progress(appContext, "$reason: 已降级为不持久化排期（重启后需重开 App 才恢复排期）") }
                runCatching { AppLog.record(AuthWorkWiring.keyValueStore(appContext), "$reason: 降级为 setPersisted(false) 排期成功") }
            }
            .onFailure { fallbackError ->
                val failDetail = "$reason: 降级排期同样失败：${fallbackError.javaClass.simpleName}: ${fallbackError.message}"
                runCatching { AuthWorkWiring.progress(appContext, failDetail) }
                runCatching { AppLog.record(AuthWorkWiring.keyValueStore(appContext), failDetail) }
            }
            .getOrDefault(false)
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

    /**
     * 【dozefix1 任务 A 段 · 核心】AlarmManager 定期保底通道的入队：**一次性** JobScheduler 任务，
     * 但 jobId = [JOB_ID_PERIODIC_CHECK]，在 [AuthJobService] 里与周期任务**同级语义**（periodic=true）
     * → 同一套 450s 去抖 + 既有四段判断链，认证仍在后台线程执行。
     *
     * 为什么由闹钟触发、仍交给 JobScheduler 执行：AlarmManager 投递的广播跑在**主线程**且只有约 10 秒
     * 预算，而认证是可能几十秒的阻塞 IO（真机崩过 NetworkOnMainThreadException）→
     * 闹钟只负责「穿透 Doze 叫醒」，真正干活沿用既有的 [AuthJobService] 后台线程。
     *
     * 为什么不复用 [AuthJobs.JOB_ID_PERIODIC]：JobScheduler 同 jobId 是**覆盖**语义，
     * 用它排一次性任务会把 15 分钟周期任务顶掉 → 两条通道就无法并存了（见 B 段的取舍）。
     */
    fun enqueuePeriodicCheck(reason: String): Boolean {
        val scheduler = js ?: return false
        return try {
            // 刻意 persisted=false：本任务由闹钟叫醒后**立刻**执行，没有「跨重启保留」的语义；
            // 重启后的补排由 AuthJobService 里的 MorningAuthRuntime.ensurePeriodicCheck 负责。
            scheduler.schedule(buildPeriodicCheckInfo(persisted = false))
            recordSchedule("$reason:ALARM_PERIODIC", 0L)
            true
        } catch (e: RuntimeException) {
            handleScheduleFailure(e, "periodic-check", reason) {
                scheduler.schedule(buildPeriodicCheckInfo(persisted = false))
                true
            }
        }
    }

    /** 构造「定期保底闹钟通道」的一次性 [JobInfo]（无最小延迟 = 尽快执行）。 */
    private fun buildPeriodicCheckInfo(persisted: Boolean): JobInfo =
        JobInfo.Builder(JOB_ID_PERIODIC_CHECK, AuthJobs.component(appContext))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(persisted)
            .setBackoffCriteria(
                JobInfo.DEFAULT_INITIAL_BACKOFF_MILLIS,
                JobInfo.BACKOFF_POLICY_EXPONENTIAL
            )
            .build()

    companion object {
        const val EXTRA_REASON = "reason"

        /**
         * 【dozefix1 任务 A 段】AlarmManager 定期保底唤窗通道的一次性任务 id。
         * 与 [AuthJobs.JOB_ID_PERIODIC] **必须不同**：JobScheduler 同 jobId 会互相覆盖。
         */
        const val JOB_ID_PERIODIC_CHECK = 0x5A03

        /** 周期任务去抖间隔（秒）：周期保底唤醒时，距上次尝试不足该值则不重复请求。 */
        fun minRetryIntervalSecondsFor(periodicIntervalMinutes: Long): Long =
            periodicIntervalMinutes.coerceAtLeast(1L) * 60L / 2L

        /**
         * 【dozefix1 · 纯逻辑】下一次「定期保底闹钟」的时刻 = now + 间隔（默认 15 分钟）。
         * 不引用任何 Android API，可在 JVM 上直接复核（见 artifacts/dozefix1/jvm-schedule-test.txt）。
         */
        fun nextPeriodicCheckAt(
            nowMillis: Long,
            intervalMinutes: Long = AuthJobs.PERIODIC_INTERVAL_MINUTES.toLong()
        ): Long = nowMillis + intervalMinutes.coerceAtLeast(1L) * 60_000L

        /**
         * 【dozefix1 · 纯逻辑】定期保底闹钟的**排期决策**（开关联动，可离线复核）：
         * 停用 → `null`（语义 = 取消，且**不重排**）；启用 → now + 间隔。
         * 同一输入重复调用结果相同（幂等）——闹钟本身的幂等由「同 requestCode ⇒ 同一 PendingIntent ⇒
         * `setExactAndAllowWhileIdle` 覆盖旧闹钟」保证。
         */
        fun nextPeriodicCheckAtOrNull(enabled: Boolean, nowMillis: Long): Long? =
            if (enabled) nextPeriodicCheckAt(nowMillis) else null
    }
}
