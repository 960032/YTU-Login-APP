package top.ytu.srunautologin.work

import top.ytu.srunautologin.auth.AuthCodes
import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.flow.AuthFlowOutcome

/**
 * 退避重试策略（模块 work，**纯 JVM，不引用任何 Android API**）。
 *
 * 设计要点（基准卡 B4）：
 *  - 失败按**指数退避**：首次失败延迟 [baseDelaySeconds] 秒，之后每次 ×[factor]，上限 [maxDelaySeconds]；
 *  - 最多尝试 [maxAttempts] 次，达到上限后**停止并记录状态**，绝不无限快速重试（避免打爆 Portal）；
 *  - 成功即清零计数；
 *  - **不在这里判断 SSID**：当前 SSID 与目标 SSID 是否匹配完全交给已冻结的
 *    `flow.AuthFlow`（B8）。本策略只解释 AuthFlow 返回的 code。
 */
data class RetryPolicy(
    val baseDelaySeconds: Int = 30,
    val factor: Int = 2,
    val maxAttempts: Int = 5,
    val maxDelaySeconds: Int = 3600
) {
    init {
        require(baseDelaySeconds > 0) { "首次退避延迟必须为正" }
        require(factor >= 1) { "退避系数必须 >= 1" }
        require(maxAttempts >= 1) { "最大尝试次数必须 >= 1" }
    }

    /** 第 attempt 次失败后的退避秒数（attempt 从 1 开始计）。attempt 超出上限仍返回上限值，不抛异常。 */
    fun delaySecondsFor(attempt: Int): Long {
        val n = attempt.coerceAtLeast(1)
        var delay = baseDelaySeconds.toLong()
        var i = 1
        while (i < n) {
            delay *= factor.toLong()
            if (delay >= maxDelaySeconds) return maxDelaySeconds.toLong()
            i++
        }
        return delay.coerceAtMost(maxDelaySeconds.toLong())
    }

    /**
     * 当前次数是否已经停止再增长（[delaySecondsFor] 到达封顶）。
     * 用于测试与报告：证明「不会无限翻倍」。
     */
    fun isSaturated(attempt: Int): Boolean = delaySecondsFor(attempt) >= maxDelaySeconds.toLong()

    /** 首次达到封顶的尝试序号（从 1 开始）；永不封顶时返回 -1。 */
    fun saturationAttempt(): Int {
        for (n in 1..64) {
            if (delaySecondsFor(n) >= maxDelaySeconds.toLong()) return n
        }
        return -1
    }

    /** 完整退避序列（自检/报告用；长度 = maxAttempts）。 */
    fun scheduleSeconds(): List<Long> = (1..maxAttempts).map { delaySecondsFor(it) }
}

/**
 * 一次调度运行的**决定**（纯数据，由 [RetryPolicy] + [AuthFlowOutcome] 推出）。
 *
 * 四选一，互斥；由调度层（Android 侧）翻译成 JobScheduler/WorkManager 的排期动作。
 */
sealed interface ScheduleDecision {
    /** 本次运行成功，无需再排期（等下一次触发/周期保底）。 */
    data object Done : ScheduleDecision

    /** 达到退避上限，停止重试；写状态并等待下一次周期保底或新触发。 */
    data class GiveUp(val attempts: Int, val lastCode: String) : ScheduleDecision

    /** 本次不消耗重试次数，短暂延迟后再试（等待 WiFi 就绪 / 连接稳定）。 */
    data class RetrySoon(val delaySeconds: Long, val reason: String) : ScheduleDecision

    /** 本次不消耗重试次数，等到 `minIntervalSeconds` 后再检查（例如退避窗口未到）。 */
    data class WaitForWindow(val delaySeconds: Long) : ScheduleDecision

    /** 按指数退避排期下一次重试（第 attempt 次失败 → 已消耗一次重试次数）。 */
    data class Backoff(val attempt: Int, val delaySeconds: Long) : ScheduleDecision
}

/**
 * 退避调度器：把「尝试次数 + 上次时间 + AuthFlow 结果」映射成 [ScheduleDecision]。
 *
 * 【B8 语义的消费方式】AuthFlow 返回 `E_SKIP_*` 表示「SSID 与绑定目标不匹配 / 无绑定 / 读不到 SSID」，
 * 此时**一个字节的认证请求都没发出**（零请求）。因此：
 *  - 它不是「失败」，不消耗退避次数；
 *  - 但继续立刻调用也没有意义（局面没变），所以安排 [ScheduleDecision.RetrySoon]（短延迟复检）；
 *  - 真正发过请求的失败（E_NETWORK / E_PORTAL / E_REJECTED …）才消耗退避次数。
 *
 * 【A1 冷启动时序】开机后 WiFi 可能尚未就绪 → AuthFlow 会返回 `E_SKIP_NO_SSID`
 * （`NO_CURRENT_SSID`）或 `E_SKIP_SSID_MISMATCH`（还连在别的网络上），
 * 两者都走 [ScheduleDecision.RetrySoon]，而不是记一次失败。
 */
class BackoffScheduler(
    /** 使用的退避策略（公开只读，供调度层与状态文本引用同一个真相来源）。 */
    val policy: RetryPolicy = RetryPolicy(),
    /** 等待 WiFi 就绪的短延迟（秒）。 */
    val networkWaitSeconds: Long = 30
) {

    /**
     * @param outcome           AuthFlow 本次的返回（Skipped = 零请求；Done = 真打过 Portal）
     * @param attemptsSoFar     已消耗的失败重试次数（**不含本次**）
     * @param lastAttemptAtMillis 上一次尝试的时刻（毫秒）；<=0 表示没有历史
     * @param nowMillis         当前时刻（毫秒）
     * @param lastRequestAtMillis 上一次**真正发起过 HTTP 请求**的时刻（毫秒）；<=0 表示还没发过请求。
     *        退避窗口只由「真请求」驱动 —— 零请求的 E_SKIP_* 不该被退避窗口挡住，
     *        否则「开机 → 等 WiFi 就绪 → 复检」会被误判成「窗口没到」而一直空转。
     */
    fun decide(
        outcome: AuthFlowOutcome,
        attemptsSoFar: Int,
        lastAttemptAtMillis: Long,
        nowMillis: Long,
        lastRequestAtMillis: Long = lastAttemptAtMillis
    ): ScheduleDecision {
        val attempts = attemptsSoFar.coerceAtLeast(0)

        // 成功：清零，不需要再排期（等待下一次触发）
        if (outcome is AuthFlowOutcome.Done && outcome.result.ok) {
            return ScheduleDecision.Done
        }

        val code = codeOf(outcome)
        val zeroRequestSkip = isZeroRequestSkip(code)

        // ---- 退避窗口闸门（先闸门、后计数，保证语义可推演）----
        // 未达上限时：上一次**真发过请求**的失败约定的等待时长 = delaySecondsFor(上次失败后的计数)，
        // 也就是 delaySecondsFor(attemptsSoFar)。窗口未到就只等待、不重复发请求。
        // 达上限后：给最后一次尝试同样长度的冷静窗口（避免系统重投把队列打满），
        // 窗口过去后本次运行判定为 GIVE_UP 并停止。
        if (windowRemainingSeconds(attempts, lastRequestAtMillis, nowMillis) > 0L && !zeroRequestSkip) {
            return ScheduleDecision.WaitForWindow(windowRemainingSeconds(attempts, lastRequestAtMillis, nowMillis))
        }

        // 退避预算耗尽：真失败 → 停止（GIVE_UP）；B8 零请求跳过 → 继续按网络变化复检
        if (attempts >= policy.maxAttempts) {
            return if (zeroRequestSkip) {
                ScheduleDecision.RetrySoon(networkWaitSeconds, code)
            } else {
                ScheduleDecision.GiveUp(attempts, code)
            }
        }

        // B8 零请求分支：不消耗重试次数，等 WiFi/绑定局面变化（A1 冷启动时序）
        if (zeroRequestSkip) {
            return ScheduleDecision.RetrySoon(networkWaitSeconds, code)
        }

        // 真的发过请求的失败 → 指数退避：本次消耗第 (attempts + 1) 次，下一次等待 delaySecondsFor(attempts + 1)
        val next = attempts + 1
        return ScheduleDecision.Backoff(next, policy.delaySecondsFor(next))
    }

    /**
     * 距离「上一次真发过请求的失败所约定的等待窗口」结束还有多少秒；
     * 返回 0 表示窗口已过（或从未发过请求）→ 可以发起请求。
     *
     * 这是**排期前的闸门**：调度层必须在调用 AuthFlow **之前**用它判断，
     * 否则「窗口未到」的判断会退化成事后检查，仍然会打一次 Portal。
     */
    fun windowRemainingSeconds(attempts: Int, lastRequestAtMillis: Long, nowMillis: Long): Long {
        if (attempts < 1 || lastRequestAtMillis <= 0L) return 0L
        val windowSeconds = policy.delaySecondsFor(attempts)
        val elapsedSeconds = ((nowMillis - lastRequestAtMillis) / 1000L).coerceAtLeast(0L)
        return (windowSeconds - elapsedSeconds).coerceAtLeast(0L)
    }

    companion object {
        /** AuthFlow 结果里的 code（Skipped 走 AuthSkip 的结构化结果，code 即 E_SKIP_*）。 */
        fun codeOf(outcome: AuthFlowOutcome): String = when (outcome) {
            is AuthFlowOutcome.Done -> outcome.result.code
            is AuthFlowOutcome.Skipped -> outcome.reason.code
        }

        /** E_SKIP_* 判定：AuthFlow 的契约前缀，表示「零请求」。 */
        fun isZeroRequestSkip(code: String): Boolean = code.startsWith(SKIP_CODE_PREFIX)

        /**
         * 是否为「重试也没用、必须等用户」的配置类失败。
         * 供状态区显示用（不改变调度语义）。
         */
        fun isConfigError(code: String): Boolean = code == AuthCodes.E_CONFIG

        /** 已冻结的 AuthFlow 跳过码前缀（只读引用，不改动 flow 模块）。 */
        const val SKIP_CODE_PREFIX: String = "E_SKIP_"

        /** 从结构化结果里取出「失败原因」文本（供状态回写）。 */
        fun messageOf(result: AuthResult?): String = result?.msg.orEmpty()
    }
}
