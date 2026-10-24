package top.ytu.srunautologin.work

import top.ytu.srunautologin.auth.AuthCodes
import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.flow.AuthFlowOutcome

data class RetryPolicy(
    val baseDelaySeconds: Int = 30,
    val factor: Int = 2,
    val maxAttempts: Int = 5,
    val maxDelaySeconds: Int = 3600
) {
    init {
        require(baseDelaySeconds > 0) { "首次退避延迟必须为正" }
        require(factor >= 1) { "退避系数必须 >= 1" }
        require(maxDelaySeconds > 0)
        require(maxAttempts in 1..100) { "最大尝试次数必须 >= 1" }
    }

    fun delaySecondsFor(attempt: Int): Long {
        if (factor == 1) return minOf(baseDelaySeconds, maxDelaySeconds).toLong()
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

    fun isSaturated(attempt: Int): Boolean = delaySecondsFor(attempt) >= maxDelaySeconds.toLong()

    fun saturationAttempt(): Int {
        for (n in 1..64) {
            if (delaySecondsFor(n) >= maxDelaySeconds.toLong()) return n
        }
        return -1
    }

    fun scheduleSeconds(): List<Long> = (1..maxAttempts).map { delaySecondsFor(it) }
}

sealed interface ScheduleDecision {
    data object Done : ScheduleDecision

    data class GiveUp(val attempts: Int, val lastCode: String) : ScheduleDecision

    data class RetrySoon(val delaySeconds: Long, val reason: String) : ScheduleDecision

    data class WaitForWindow(val delaySeconds: Long) : ScheduleDecision

    data class Backoff(val attempt: Int, val delaySeconds: Long) : ScheduleDecision
}

class BackoffScheduler(
    val policy: RetryPolicy = RetryPolicy(),
    val networkWaitSeconds: Long = 30
) {

    fun decide(
        outcome: AuthFlowOutcome,
        attemptsSoFar: Int,
        lastAttemptAtMillis: Long,
        nowMillis: Long,
        lastRequestAtMillis: Long = lastAttemptAtMillis
    ): ScheduleDecision {
        val attempts = attemptsSoFar.coerceAtLeast(0)
        val code = codeOf(outcome)
        if ((outcome is AuthFlowOutcome.Done && outcome.result.ok) || code == "E_SKIP_ALREADY_ONLINE")
            return ScheduleDecision.Done
        if (code == "E_SKIP_IN_PROGRESS") return ScheduleDecision.WaitForWindow(5)
        if (isZeroRequestSkip(code)) return ScheduleDecision.RetrySoon(0, code)
        if (isConfigError(code) || (outcome is AuthFlowOutcome.Done &&
                    outcome.result.failure == top.ytu.srunautologin.auth.AuthFailure.REJECTED))
            return ScheduleDecision.GiveUp(attempts, code)
        val remaining = windowRemainingSeconds(attempts, lastRequestAtMillis, nowMillis)
        if (remaining > 0) return ScheduleDecision.WaitForWindow(remaining)
        if (attempts >= policy.maxAttempts) return ScheduleDecision.GiveUp(attempts, code)
        val next = attempts + 1
        return if (next >= policy.maxAttempts) ScheduleDecision.GiveUp(next, code)
            else ScheduleDecision.Backoff(next, policy.delaySecondsFor(next))
    }

    fun windowRemainingSeconds(attempts: Int, lastRequestAtMillis: Long, nowMillis: Long): Long {
        if (attempts < 1 || lastRequestAtMillis <= 0L) return 0L
        val windowSeconds = policy.delaySecondsFor(attempts)
        val elapsedSeconds = ((nowMillis - lastRequestAtMillis) / 1000L).coerceAtLeast(0L)
        return (windowSeconds - elapsedSeconds).coerceAtLeast(0L)
    }

    companion object {
        fun codeOf(outcome: AuthFlowOutcome): String = when (outcome) {
            is AuthFlowOutcome.Done -> outcome.result.code
            is AuthFlowOutcome.Skipped -> outcome.reason.code
        }

        fun isZeroRequestSkip(code: String): Boolean = code.startsWith(SKIP_CODE_PREFIX)

        fun isConfigError(code: String): Boolean = code in setOf(
            AuthCodes.E_CONFIG, AuthCodes.E_INSECURE_PORTAL, AuthCodes.E_TLS,
            AuthCodes.E_REDIRECT, AuthCodes.E_RESPONSE_LIMIT, AuthCodes.E_REJECTED)

        const val SKIP_CODE_PREFIX: String = "E_SKIP_"

        fun messageOf(result: AuthResult?): String = result?.msg.orEmpty()
    }
}
