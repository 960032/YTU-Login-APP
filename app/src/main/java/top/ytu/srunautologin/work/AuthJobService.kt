package top.ytu.srunautologin.work

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Context
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthSkipReason
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
        // 【logfix1 任务 B 段】调度埋点：JobScheduler 真正唤起了后台任务
        runCatching {
            top.ytu.srunautologin.log.AppLog.record(
                top.ytu.srunautologin.platform.SrunStorage.keyValueStore(this),
                "调度：JobScheduler 触发后台任务（jobId=$jobId，来源 $reason，periodic=$periodic）"
            )
        }

        // restoretoggle1（用户要求）：闸门恢复 —— **停用时周期保底也不执行**（与网络变化通道同口径）。
        // 位置在 onStartJob 内、两条调度埋点之后：停用就直接收工，不跑认证、不排重试。
        AutoLoginSwitch.gateReason(
            top.ytu.srunautologin.platform.SrunStorage.keyValueStore(this),
            "AuthJobService.onStartJob（periodic=$periodic）"
        )?.let { reason ->
            AuthWorkWiring.progress(this, reason)
            runCatching {
                top.ytu.srunautologin.log.AppLog.record(
                    top.ytu.srunautologin.platform.SrunStorage.keyValueStore(this),
                    "调度：$reason"
                )
            }
            return false
        }

        // removemorning1：原「周期兜底为早上例程让路」的分支已删除 ——
        // 早上例程（06:00 首次 + 每 10 分钟重试、每天 7 次）已按用户要求整体取消，
        // 不再存在「刚跑过的早上尝试」需要让路；周期保底恢复为无条件的 15 分钟通道。

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
                // 【logfix1 任务 B 段】调度埋点：后台任务收尾（成功/失败/放弃/重试在 AuthWorkCoordinator
                // 的日志里已有明细，这里只记「本次任务结束 + 是否要系统重投」）
                runCatching {
                    top.ytu.srunautologin.log.AppLog.record(
                        top.ytu.srunautologin.platform.SrunStorage.keyValueStore(this),
                        "调度：后台任务结束（trigger=${result.trigger.wireName}，outcome=${result.outcome.wireName}，" +
                            "code=${result.code}，delay=${result.delaySeconds}s）"
                    )
                }
                when (result.outcome) {
                    // 收工：不再排期（等下一次触发/周期保底）
                    RunOutcome.SUCCESS, RunOutcome.GIVE_UP, RunOutcome.NO_CREDENTIAL, RunOutcome.NO_PERMISSION -> false
                    // 【Bug C 修复（removemorning1）】零请求跳过必须**再细分**：
                    RunOutcome.SKIPPED_ZERO_REQUEST -> when (result.code) {
                        // ① 「服务端返回已在线」（code=E_SKIP_ALREADY_ONLINE）是**成功达成目标**：
                        //    本次要达成的目标就是「处于已登录状态」，此刻已经满足
                        //    → **不排任何重试**、直接收工（也不变更任何计数）。
                        //    修复前它落进下面那条分支 → 排 30 秒重试
                        //    （用户真机日志：「调度：安排重试（第 3/5 次，延迟 30s，原因 E_SKIP_ALREADY_ONLINE）」）
                        //    → 反复无意义打 Portal。全链路核查见 fix-report.md 的 C 段。
                        AuthSkipReason.ALREADY_ONLINE.code -> false
                        // ② 其它 E_SKIP_*（E_SKIP_NO_SSID / E_SKIP_UNBOUND / E_SKIP_SSID_MISMATCH /
                        //    E_SKIP_NOT_SRUN / E_SKIP_PROBE_UNCERTAIN）行为**保持不变**：
                        //    它们确实需要等「网络变化 / 探测闸门」后复检，保留原有短延迟重试。
                        else -> {
                            AuthWorkWiring.scheduler(this).enqueueAuth(
                                delayMillis = result.delaySeconds * 1000L,
                                reason = "retry-after-${result.code}"
                            )
                            false
                        }
                    }
                    // 继续重试：由 App 自己的退避策略给出延迟
                    RunOutcome.RETRY_SCHEDULED, RunOutcome.WAITING -> {
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
         *
         * @param context 调用方提供的 Context。companion 作用域里既没有 Service 实例，
         *        也没有静态 applicationContext，所以必须由调用方显式传入（内部只用 applicationContext）。
         */
        fun runInline(context: Context, targetSsid: String?, trigger: TriggerKind): AuthRunResult {
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
