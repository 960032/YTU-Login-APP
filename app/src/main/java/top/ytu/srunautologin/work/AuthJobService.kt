package top.ytu.srunautologin.work

import android.app.job.JobParameters
import android.app.job.JobService
import top.ytu.srunautologin.flow.AuthFlow
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * ============================ Android 边界层（未验证部分，理由同 AuthScheduler.kt）============
 *
 * 真正的后台执行体：由 [AndroidAuthScheduler] 排期，跑一次 [AuthWorkCoordinator.run]，
 * 按结果决定是否继续退避排期。
 *
 * **不使用前台服务**：前台服务会常驻通知，且 Android 12+（API 31）对后台启动前台服务有硬限制；
 * 认证是秒级任务，JobScheduler 的普通后台任务完全够用（详见 ci-notes.md 的取舍说明）。
 */
class AuthJobService : JobService() {

    /** 认证是阻塞 IO，放到单线程池执行，避免占用主线程。 */
    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "srun-auth-job").apply { isDaemon = true }
    }

    override fun onStartJob(params: JobParameters?): Boolean {
        val p = params ?: return false
        val jobId = p.jobId
        val periodic = jobId == AuthJobs.JOB_ID_PERIODIC
        val reason = jobIdName(jobId)
        AuthWorkWiring.progress(this, "onStartJob: jobId=$jobId reason=$reason")

        worker.execute {
            // 结果与「是否需要系统重投」解耦，避免把「到上限停止」误当成失败重试
            val needSystemRetry = try {
                val result = AuthWorkWiring.run(
                    context = this,
                    trigger = if (periodic) TriggerKind.PERIODIC else TriggerKind.NETWORK,
                    periodic = periodic
                )
                AuthWorkWiring.progress(
                    this,
                    "run done: outcome=${result.outcome.wireName} code=${result.code} " +
                        "attempt=${result.attempt}/${AuthWorkWiring.maxAttempts(this)} " +
                        "delay=${result.delaySeconds}s"
                )
                when (result.outcome) {
                    // 收工：不再排期（等下一次触发/周期保底）
                    RunOutcome.SUCCESS, RunOutcome.GIVE_UP, RunOutcome.NO_CREDENTIAL, RunOutcome.NO_PERMISSION -> false
                    // 继续重试：由 App 自己的退避策略给出延迟
                    RunOutcome.RETRY_SCHEDULED, RunOutcome.SKIPPED_ZERO_REQUEST, RunOutcome.WAITING -> {
                        AuthWorkWiring.scheduler(this).enqueueAuth(
                            delayMillis = result.delaySeconds * 1000L,
                            reason = "retry-after-${result.code}"
                        )
                        false
                    }
                }
            } catch (e: Throwable) {
                // 兜底：任何未预期异常都必须落盘，绝不静默消失
                AuthWorkWiring.progress(this, "run crashed: ${e.javaClass.name}: ${e.message}")
                AuthWorkWiring.keyValueStore(this).putString(
                    AuthStatusKeys.STATUS_TEXT,
                    "[后台:$reason] 调度异常（${e.javaClass.simpleName}）：${e.message}"
                )
                AuthWorkWiring.scheduler(this).enqueueAuth(
                    delayMillis = AuthWorkWiring.retryPolicy(this).baseDelaySeconds * 1000L,
                    reason = "crash-retry"
                )
                false
            }
            // 有后台线程在工作 → onStartJob 返回 true，完成时必须调用 jobFinished
            jobFinished(p, needSystemRetry)
        }
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        AuthWorkWiring.progress(this, "onStopJob: jobId=${params?.jobId}（系统抢占；排期已持久化，稍后会重投）")
        // true = 保留排期让系统稍后重投，避免任务被静默丢弃
        return true
    }

    companion object {
        /**
         * 同步执行一次认证（供前台「立即登录」复用同一装配，不经过 JobScheduler）。
         * 超时返回 [RunOutcome.WAITING] 的结果，绝不返回 null。
         */
        fun runInline(targetSsid: String?, trigger: TriggerKind): AuthRunResult {
            val latch = CountDownLatch(1)
            var out: AuthRunResult? = null
            val executor = Executors.newSingleThreadExecutor { r ->
                Thread(r, "srun-auth-inline").apply { isDaemon = true }
            }
            executor.execute {
                try {
                    out = AuthWorkWiring.run(context, trigger, periodic = false, targetOverride = targetSsid)
                } catch (e: Throwable) {
                    AuthWorkWiring.progress(context, "inline run crashed: ${e.javaClass.name}: ${e.message}")
                } finally {
                    latch.countDown()
                }
            }
            latch.await(120, TimeUnit.SECONDS)
            executor.shutdown()
            return out ?: AuthRunResult(
                outcome = RunOutcome.WAITING, code = "E_TIMEOUT", message = "前台同步认证等待超时",
                authOk = false, trigger = trigger, attempt = 0, attemptsConsumed = false,
                finishedAtMillis = System.currentTimeMillis(), delaySeconds = 0, ranFlow = false,
                statusLine = ""
            )
        }

        private fun jobIdName(jobId: Int): String = when (jobId) {
            AuthJobs.JOB_ID_PERIODIC -> "periodic"
            AuthJobs.JOB_ID_AUTH_ONCE -> "auth-once"
            else -> "job-$jobId"
        }
    }
}
