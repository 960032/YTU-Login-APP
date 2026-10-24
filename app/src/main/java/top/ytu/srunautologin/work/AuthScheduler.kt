package top.ytu.srunautologin.work

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.os.Build
import java.util.concurrent.TimeUnit

object AuthJobs {
    const val JOB_ID_AUTH_ONCE = 23041
    const val JOB_ID_PERIODIC = 23042
    const val PERIODIC_INTERVAL_MINUTES = 15
    const val PERIODIC_FLEX_MINUTES = 5
    const val MAX_DELAY_MILLIS = 13L * 24 * 60 * 60 * 1000
    fun component(context: Context) = ComponentName(context.applicationContext, AuthJobService::class.java)
}

/** Login establishes connectivity: none of these jobs require validated Internet. */
class AndroidAuthScheduler(context: Context, private val minRetryIntervalMinutes: Long = 15L) {
    private val appContext = context.applicationContext
    private val jobs = appContext.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler

    private fun authInfo(id: Int, delay: Long, persisted: Boolean): JobInfo =
        JobInfo.Builder(id, AuthJobs.component(appContext))
            .setMinimumLatency(delay.coerceIn(0L, AuthJobs.MAX_DELAY_MILLIS))
            .setPersisted(persisted)
            .setBackoffCriteria(30_000L, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
            .build()

    private fun periodicInfo(persisted: Boolean): JobInfo =
        JobInfo.Builder(AuthJobs.JOB_ID_PERIODIC, AuthJobs.component(appContext))
            .setPeriodic(TimeUnit.MINUTES.toMillis(15), TimeUnit.MINUTES.toMillis(5))
            .setPersisted(persisted)
            .build()

    private fun schedule(reason: String, build: (Boolean) -> JobInfo): Boolean {
        val scheduler = jobs ?: run { record("排期失败：系统调度服务不可用（$reason）"); return false }
        return try {
            val success = scheduler.schedule(build(true)) == JobScheduler.RESULT_SUCCESS
            record(if (success) "任务已入队（$reason）" else "排期失败：系统拒绝任务（$reason）")
            success
        } catch (e: RuntimeException) {
            record("持久化排期失败（$reason，${e.javaClass.simpleName}），尝试非持久化任务")
            try {
                val success = scheduler.schedule(build(false)) == JobScheduler.RESULT_SUCCESS
                record(if (success) "任务已入队，重启后由开机接收器恢复（$reason）"
                       else "排期失败：系统拒绝降级任务（$reason）")
                success
            } catch (fallback: RuntimeException) {
                record("排期失败（$reason，${fallback.javaClass.simpleName}）")
                false
            }
        }
    }

    @Synchronized
    fun enqueueAuth(delayMillis: Long, reason: String): Boolean = synchronized(SCHEDULE_LOCK) {
        if (jobs?.getPendingJob(AuthJobs.JOB_ID_AUTH_ONCE) != null) {
            record("合并认证触发：已有待执行或执行中的任务（$reason）")
            return true
        }
        return enqueueAuthReplacing(delayMillis, reason)
    }

    fun enqueueAuthReplacing(delayMillis: Long, reason: String): Boolean =
        schedule(reason) { authInfo(AuthJobs.JOB_ID_AUTH_ONCE, delayMillis, it) }

    fun enqueuePeriodicCheck(reason: String): Boolean {
        if (jobs?.getPendingJob(JOB_ID_PERIODIC_CHECK) != null) return true
        return schedule(reason) { authInfo(JOB_ID_PERIODIC_CHECK, 0L, it) }
    }

    fun ensurePeriodic(): Boolean {
        val current = jobs?.getPendingJob(AuthJobs.JOB_ID_PERIODIC)
        @Suppress("DEPRECATION")
        val noNetworkConstraint = current != null && if (Build.VERSION.SDK_INT >= 28)
            current.requiredNetwork == null else current.networkType == JobInfo.NETWORK_TYPE_NONE
        if (current != null && current.isPeriodic && current.isPersisted && noNetworkConstraint) return true
        return schedule("periodic-fallback") { periodicInfo(it) }
    }

    /** Compatibility entry point; no unconsumed/persisted JobWorkItem queue. */
    fun enqueueWorkItem(reason: String): Boolean = enqueueAuth(0L, reason)

    fun cancelPendingAuth() { jobs?.cancel(AuthJobs.JOB_ID_AUTH_ONCE) }
    fun cancelAll() {
        listOf(AuthJobs.JOB_ID_AUTH_ONCE, AuthJobs.JOB_ID_PERIODIC, JOB_ID_PERIODIC_CHECK).forEach { jobs?.cancel(it) }
    }

    private fun record(message: String) { AuthWorkWiring.progress(appContext, "调度：$message") }

    companion object {
        private val SCHEDULE_LOCK = Any()
        const val EXTRA_REASON = "reason"
        const val JOB_ID_PERIODIC_CHECK = 23043
        fun minRetryIntervalSecondsFor(minutes: Long): Long = (minutes.coerceAtLeast(1L) * 60L) / 2L
        fun nextPeriodicCheckAt(now: Long, intervalMinutes: Long = 15L): Long =
            now + TimeUnit.MINUTES.toMillis(intervalMinutes.coerceAtLeast(1L))
        fun nextPeriodicCheckAtOrNull(enabled: Boolean, now: Long): Long? =
            if (enabled) nextPeriodicCheckAt(now) else null
    }
}
