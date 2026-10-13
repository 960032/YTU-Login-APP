package top.ytu.srunautologin.work

import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.AuthSkipReason
import top.ytu.srunautologin.log.AppLog

/**
 * 一次后台运行的结果（纯数据）。
 *
 * @param ranFlow 是否真的调用了 [AuthFlow.run]（false = 被退避窗口/WiFi 快速返回拦下，未触碰 flow）
 */
data class AuthRunResult(
    val outcome: RunOutcome,
    val code: String,
    val message: String,
    val authOk: Boolean,
    val trigger: TriggerKind,
    val attempt: Int,
    val attemptsConsumed: Boolean,
    val finishedAtMillis: Long,
    val delaySeconds: Long,
    val ranFlow: Boolean,
    val statusLine: String
)

/**
 * 后台认证协调器（模块 work 的**唯一编排入口**，纯 JVM + Android 双用）。
 *
 * 职责边界（严格遵守基准卡，避免两套真相）：
 *  1. 触发条件判定：退避窗口是否已到、当前是否具备运行条件（**只读 [KeyValueStore] 中的状态**）；
 *  2. 调用**已冻结的** [AuthFlow.run]（B8 的 SSID 匹配判断全在 flow 模块内部，
 *     本类**没有**任何 `currentSsid == targetSsid` 之类的比较，也没有直接读 WifiAccountMap）；
 *  3. 按 [BackoffScheduler] 决定下一次排期；
 *  4. 把结果写进 [AuthStatusStore]（B5），并持久化退避计数。
 *
 * 【A1 冷启动时序】开机后 WiFi 未就绪时，AuthFlow 返回 `E_SKIP_NO_SSID`（零请求），
 * 本类据此走 [RunOutcome.SKIPPED_ZERO_REQUEST] → 短延迟复检，**不记为失败**、不消耗退避次数。
 *
 * @param minRetryIntervalSeconds 两次「真发请求」之间的最小间隔（周期任务唤醒时的去抖）；
 *        为 0 表示不限制（例如用户在界面上手动点了「立即登录」，必须立刻生效）。
 */
class AuthWorkCoordinator(
    private val flow: AuthFlow,
    private val store: AuthStatusStore,
    private val scheduler: BackoffScheduler = BackoffScheduler(),
    private val trigger: TriggerKind,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val minRetryIntervalSeconds: Long = 0L
) {

    /**
     * 【logfix1 任务 B 段】日志写入缝（真机 = `AppLog.record(kv, line)`；null = 不写应用内日志，
     * 既有离线核对的老调用点行为不变）。
     *
     * **为什么是可变属性而不是构造参数**（与 [AuthFlow] 同一教训，实测证据见 artifacts/logfix1/verify-proof.txt）：
     * 既有离线核对快照按「6 个参数 + 1 个默认掩码」的合成默认构造直接调用本类：
     * `(AuthFlow, AuthStatusStore, BackoffScheduler, TriggerKind, Function0<Long>, long, int, DefaultConstructorMarker)`。
     * 在构造参数列表里新增一项后，合成默认构造变成 9 个参数 → 快照侧抛 NoSuchMethodError。
     * 因此构造签名**逐字冻结**，日志缝在真机装配点构造完成后注入。
     *
     * **为什么是 `(String) -> Unit` 而不是 `android.content.Context`**：本文件在既有离线核对里是
     * 「纯逻辑文件」（W42 断言：纯逻辑文件不得 `import android.`）。把签名写成 Context 会把 Android
     * 类型传染进 work 层的纯逻辑文件；写成函数类型则由 Android 边界层（AuthWorkWiring / AuthJobService）
     * 在构造后注入 `{ line -> AppLog.record(kv, line) }`，本文件保持**零 android import**。
     */
    var log: ((String) -> Unit)? = null

    private val policy: RetryPolicy get() = scheduler.policy

    /**
     * 执行一次后台认证。
     *
     * @param targetSsid 目标 SSID。**必须来自用户的配置界面**（`ConfigViewModel.state.selectedSsid`
     *                   对应的持久化值）；为 null 时交给 AuthFlow 按「以当前 SSID 为准」处理。
     */
    fun run(targetSsid: String?): AuthRunResult {
        val previous = store.loadAttemptState()
        val now = clock()

        // ---- 快速返回 1：距「上一次**真发过请求**」是否还不满最小间隔（周期任务去抖） ----
        // 【logfix2 任务 D 段·根因修复】去抖的基准量必须是上次「真发过请求」的时刻
        // （[AttemptState.lastRequestAtMillis]，与下面快速返回 2 的退避窗口、[BackoffScheduler.decide]
        //  用的是同一个量），而**不是**上次「尝试」的时刻：
        //  零请求的跳过（E_SKIP_*：已在线 / SSID 不匹配 / 读不到 SSID / 探测不确定）一个字节都没发出去，
        //  它不该武装去抖窗口 —— 否则「已在线 → 跳过」会把随后**真正需要登录**的那次触发堵在门外。
        //  真机症状（用户日志逐字，periodic=false 也照样被堵）：
        //    `后台任务结束（trigger=network，outcome=waiting，code=E_WAIT，delay=428s）`
        //  ——网络变化触发的自动登录被上一次尝试留下的窗口挡住，连探测都没跑（ranFlow=false），
        //  用户感知就是「自动登录没有按预期工作」。
        //  真发过请求的失败照旧被拦在窗口外（Portal 防抖语义不变）。
        val debounceFromMillis = previous.lastRequestAtMillis
        if (minRetryIntervalSeconds > 0L && debounceFromMillis > 0L) {
            val elapsed = (now - debounceFromMillis) / 1000L
            if (elapsed < minRetryIntervalSeconds) {
                return AuthRunResult(
                    outcome = RunOutcome.WAITING,
                    code = "E_WAIT",
                    message = "距上次发起认证请求仅 ${elapsed}s，低于最小间隔 ${minRetryIntervalSeconds}s，本次不发起请求",
                    authOk = false,
                    trigger = trigger,
                    attempt = previous.attempts,
                    attemptsConsumed = false,
                    finishedAtMillis = now,
                    delaySeconds = minRetryIntervalSeconds - elapsed,
                    ranFlow = false,
                    statusLine = ""
                )
            }
        }

        // ---- 快速返回 2：指数退避窗口（**必须在调用 AuthFlow 之前判断**）----
        // 上一次失败约定的等待时长是 delaySecondsFor(attempts)。窗口未到就只返回 WAITING，
        // 绝不去打 Portal —— 否则「退避」会退化成事后检查，仍然会多发请求。
        val windowRemaining = scheduler.windowRemainingSeconds(previous.attempts, previous.lastRequestAtMillis, now)
        if (windowRemaining > 0L) {
            return AuthRunResult(
                outcome = RunOutcome.WAITING,
                code = "E_BACKOFF_WAIT",
                message = "距上次认证请求仅 ${previous.elapsedSinceLastSeconds(now) ?: 0}s，" +
                    "未到退避窗口（还需 ${windowRemaining}s），本次不发起请求",
                authOk = false,
                trigger = trigger,
                attempt = previous.attempts,
                attemptsConsumed = false,
                finishedAtMillis = now,
                delaySeconds = windowRemaining,
                ranFlow = false,
                statusLine = ""
            )
        }

        // ---- 快速返回 3：退避预算已耗尽（**同样在调用 AuthFlow 之前**）----
        // 上一次的 code 是 E_SKIP_* 时说明它没消耗预算，仍允许继续（A1 冷启动时序）。
        val lastCode = store.lastStatusCode()
        val budgetExhausted = previous.attempts >= scheduler.policy.maxAttempts &&
            (lastCode == null || !BackoffScheduler.isZeroRequestSkip(lastCode))
        if (budgetExhausted) {
            return AuthRunResult(
                outcome = RunOutcome.GIVE_UP,
                code = lastCode ?: "E_GIVE_UP",
                message = "已连续失败 ${previous.attempts} 次（上限 ${scheduler.policy.maxAttempts} 次），" +
                    "本次不再发起请求，等待下一次触发/周期保底",
                authOk = false,
                trigger = trigger,
                attempt = previous.attempts,
                attemptsConsumed = false,
                finishedAtMillis = now,
                delaySeconds = 0L,
                ranFlow = false,
                statusLine = ""
            )
        }

        // ---- 真正调用已冻结的 AuthFlow（B8 判定在其中） ----
        val outcome = flow.run(targetSsid)
        val code = BackoffScheduler.codeOf(outcome)
        val finish = clock()

        // ---- 排期决定 ----
        val decision = scheduler.decide(
            outcome = outcome,
            attemptsSoFar = previous.attempts,
            lastAttemptAtMillis = previous.lastAttemptAtMillis,
            nowMillis = now,
            // 退避窗口只由「上一次真发过请求」驱动；从未发过请求时为 0（不设窗口）
            lastRequestAtMillis = previous.lastRequestAtMillis
        )

        val consumed = decision is ScheduleDecision.Backoff
        val attempts = when (decision) {
            is ScheduleDecision.Backoff -> decision.attempt
            is ScheduleDecision.GiveUp -> decision.attempts
            else -> previous.attempts
        }
        val delay = when (decision) {
            is ScheduleDecision.Backoff -> decision.delaySeconds
            ScheduleDecision.Done, is ScheduleDecision.GiveUp -> 0L
            is ScheduleDecision.RetrySoon -> decision.delaySeconds
            is ScheduleDecision.WaitForWindow -> decision.delaySeconds
        }
        val runOutcome = when (decision) {
            is ScheduleDecision.Backoff -> RunOutcome.RETRY_SCHEDULED
            ScheduleDecision.Done -> RunOutcome.SUCCESS
            is ScheduleDecision.GiveUp -> RunOutcome.GIVE_UP
            is ScheduleDecision.RetrySoon -> RunOutcome.SKIPPED_ZERO_REQUEST
            is ScheduleDecision.WaitForWindow -> RunOutcome.WAITING
        }

        // ---- 结果对象与状态行 ----
        val authOk = (outcome is AuthFlowOutcome.Done) && outcome.result.ok
        val message = AuthStatusStore.messageOf(outcome)
        val failureName = (outcome as? AuthFlowOutcome.Done)?.result?.failure?.displayName
        val statusLine = AuthStatusStore.formatLine(
            trigger = trigger,
            atMillis = finish,
            ok = authOk,
            code = code,
            message = message,
            failureName = failureName,
            attempts = attempts,
            maxAttempts = policy.maxAttempts
        )

        // ---- 持久化（B5 状态回写 + 退避状态） ----
        // 真发过请求的时刻 = 退避窗口的唯一驱动量：只有真的调用过认证客户端才更新它
        val newLastRequestAt = if (outcome is AuthFlowOutcome.Done && !authOk) finish else previous.lastRequestAtMillis
        val newState = when {
            authOk -> AttemptState(
                seq = previous.seq + 1, attempts = 0,
                lastAttemptAtMillis = finish, firstAttemptAtMillis = 0L,
                lastRequestAtMillis = previous.lastRequestAtMillis
            )
            consumed -> AttemptState(
                seq = previous.seq + 1,
                attempts = attempts,
                lastAttemptAtMillis = finish,
                firstAttemptAtMillis = if (previous.firstAttemptAtMillis <= 0L) finish else previous.firstAttemptAtMillis,
                lastRequestAtMillis = newLastRequestAt
            )
            else -> AttemptState(
                seq = previous.seq + 1,
                attempts = previous.attempts,
                lastAttemptAtMillis = if (decision is ScheduleDecision.RetrySoon) finish else previous.lastAttemptAtMillis,
                firstAttemptAtMillis = previous.firstAttemptAtMillis,
                lastRequestAtMillis = newLastRequestAt
            )
        }
        store.saveAttemptState(newState)
        store.saveResult(text = statusLine, code = code, ok = authOk, atMillis = finish)

        val result = AuthRunResult(
            outcome = runOutcome,
            code = code,
            message = message,
            authOk = authOk,
            trigger = trigger,
            attempt = attempts,
            attemptsConsumed = consumed,
            finishedAtMillis = finish,
            delaySeconds = delay,
            ranFlow = true,
            statusLine = statusLine
        )
        logResult(result)
        return result
    }

    /** 成功 / 用户改配置后清零退避计数（由调度层在需要时调用）。 */
    fun resetBackoff() {
        val prev = store.loadAttemptState()
        store.clearAttempts(seq = prev.seq)
    }

    /**
     * 【logfix1 任务 B 段】把一次后台运行的结果写进应用内日志（与状态区同源）。
     *
     * 覆盖的事件语义（用户要求「记录本应用执行和用户输入的所有操作」）：
     *  - 调度触发（trigger）/ 退避等待 / 退避预算耗尽（放弃）/ 未配置账号 / 探测不确定；
     *  - 登录成功（服务端 code）/ 登录失败（code + 失败分类）；
     *  - 重试（第几次、延迟多少秒）。
     *
     * 隐私：账户名一律经 [AppLog.maskAccount]（只留前 3 位）；本方法**不接触密码**。
     * 失败安全：整段 runCatching —— 日志异常绝不影响认证结果。
     */
    private fun logResult(r: AuthRunResult) {
        val sink = log ?: return
        runCatching {
            val head = "[${r.trigger.wireName}]"
            val line = when (r.outcome) {
                RunOutcome.SUCCESS -> "$head 登录成功：${r.message}（code=${r.code}）"
                RunOutcome.RETRY_SCHEDULED -> "$head 登录失败：${r.message}（code=${r.code}）→ 重试第 ${r.attempt}/${policy.maxAttempts} 次，延迟 ${r.delaySeconds}s"
                RunOutcome.GIVE_UP -> "$head 登录放弃：连续失败 ${r.attempt} 次（上限 ${policy.maxAttempts} 次），code=${r.code}，不再重试"
                RunOutcome.SKIPPED_ZERO_REQUEST -> {
                    if (r.code == AuthSkipReason.PROBE_UNCERTAIN.code) {
                        val st = flow.lastProbeState
                        val attempts = st?.attempts ?: 1
                        "$head 探测不确定：${r.message}（探测第 $attempts 次）→ 本次未登录；" +
                            "将按 5 分钟间隔重试，最多 2 次（共 3 次），全部不确定则记日志后不再尝试"
                    } else {
                        "$head 跳过（零请求）：${r.message}（code=${r.code}）"
                    }
                }
                RunOutcome.WAITING -> "$head 等待：${r.message}（还需 ${r.delaySeconds}s）"
                RunOutcome.NO_CREDENTIAL -> "$head 未配置账号：${r.message}"
                RunOutcome.NO_PERMISSION -> "$head 权限缺失：${r.message}"
            }
            sink(line)
        }
    }

    /** 本轮允许的最大尝试次数（供调度层与状态文本使用）。 */
    fun maxAttempts(): Int = policy.maxAttempts
}
