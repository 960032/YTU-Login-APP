package top.ytu.srunautologin.work

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean
import top.ytu.srunautologin.platform.ActiveWifiSessions
import top.ytu.srunautologin.platform.SrunStorage

/** Every admitted job is finished once; cancelled work cannot write a late retry. */
class AuthJobService : JobService() {
    private class Task(val parameters: JobParameters) {
        val cancelled = AtomicBoolean(false)
        @Volatile var thread: Thread? = null
        @Volatile var future: Future<*>? = null
        fun cancel() {
            cancelled.set(true)
            thread?.let(ActiveWifiSessions::cancelThread)
            future?.cancel(true)
        }
    }
    private val tasks = ConcurrentHashMap<Int, Task>()
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "srun-auth-job").apply { isDaemon = true }
    }

    override fun onStartJob(params: JobParameters?): Boolean {
        val parameters = params ?: return false
        if (!AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(this))) {
            AuthWorkWiring.progress(this, "调度：自动登录已停用，取消 job=${parameters.jobId}")
            return false
        }
        val task = Task(parameters)
        tasks.put(parameters.jobId, task)?.cancel()
        val periodic = parameters.jobId != AuthJobs.JOB_ID_AUTH_ONCE
        AuthWorkWiring.progress(this, "调度：后台任务开始 job=${parameters.jobId} periodic=$periodic")
        task.future = worker.submit {
            task.thread = Thread.currentThread()
            if (task.cancelled.get()) return@submit
            val result = try {
                AuthWorkWiring.run(this, if (periodic) TriggerKind.PERIODIC else TriggerKind.NETWORK, periodic)
            } catch (e: Exception) {
                if (!task.cancelled.get()) AuthWorkWiring.progress(this,
                    "调度：任务执行异常（${e.javaClass.simpleName}），等待下一次网络事件或周期检查")
                null
            }
            main.post {
                if (!tasks.remove(parameters.jobId, task) || task.cancelled.get()) return@post
                // Finish first: scheduling the same ID while it is still running cancels it.
                jobFinished(parameters, false)
                if (result != null && result.delaySeconds > 0L &&
                    result.outcome in setOf(RunOutcome.RETRY_SCHEDULED, RunOutcome.WAITING) &&
                    AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(this))) {
                    AuthWorkWiring.scheduler(this).enqueueAuth(result.delaySeconds * 1000L, "retry-${result.code}")
                }
            }
        }
        if (task.cancelled.get()) task.future?.cancel(true)
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        val parameters = params ?: return false
        tasks.remove(parameters.jobId)?.cancel()
        AuthWorkWiring.progress(this, "调度：后台任务已取消 job=${parameters.jobId}")
        val appCancelled = Build.VERSION.SDK_INT >= 31 &&
            parameters.stopReason == JobParameters.STOP_REASON_CANCELLED_BY_APP
        return !appCancelled && AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(this))
    }

    override fun onDestroy() {
        tasks.values.forEach(Task::cancel)
        tasks.clear()
        worker.shutdownNow()
        super.onDestroy()
    }

    companion object {
        /** Worker-thread entry point for callers that do not need JobScheduler. */
        fun runInline(context: Context, targetSsid: String?, trigger: TriggerKind): AuthRunResult {
            check(Looper.myLooper() != Looper.getMainLooper()) { "认证必须在工作线程执行" }
            return AuthWorkWiring.run(context, trigger, targetOverride = targetSsid)
        }
    }
}
