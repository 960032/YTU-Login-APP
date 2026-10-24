package top.ytu.srunautologin.work

import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.AuthSkipReason
import top.ytu.srunautologin.log.AppLog

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

class AuthWorkCoordinator(
    private val flow: AuthFlow,
    private val store: AuthStatusStore,
    private val scheduler: BackoffScheduler = BackoffScheduler(),
    private val trigger: TriggerKind,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val minRetryIntervalSeconds: Long = 0L
) {

    var log: ((String) -> Unit)? = null

    private val policy: RetryPolicy get() = scheduler.policy

    fun run(targetSsid: String?): AuthRunResult {
        val previous = store.loadAttemptState()
        val now = clock()
        if (store.userActionRequired(targetSsid)) return AuthRunResult(RunOutcome.GIVE_UP,
            store.lastStatusCode() ?: "E_CONFIG", "请修改账号或门户安全配置后重试", false,
            trigger, previous.attempts, false, now, 0L, false, store.lastStatusText().orEmpty())

        val debounceFromMillis = previous.lastRequestAtMillis
        if (minRetryIntervalSeconds > 0L && debounceFromMillis > 0L) {
            val elapsed = ((now - debounceFromMillis) / 1000L).coerceAtLeast(0L)
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

        val outcome = flow.run(targetSsid)
        val code = BackoffScheduler.codeOf(outcome)
        val finish = clock()

        val decision = scheduler.decide(
            outcome = outcome,
            attemptsSoFar = previous.attempts,
            lastAttemptAtMillis = previous.lastAttemptAtMillis,
            nowMillis = now,
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

        val authOk = decision == ScheduleDecision.Done
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
        val terminal = BackoffScheduler.isConfigError(code) ||
            (outcome is AuthFlowOutcome.Done && outcome.result.failure == top.ytu.srunautologin.auth.AuthFailure.REJECTED)
        if (authOk || terminal) store.setUserActionRequired(terminal, targetSsid)
        store.saveAttemptState(if (decision is ScheduleDecision.GiveUp)
            newState.copy(attempts = decision.attempts, lastRequestAtMillis = finish) else newState)
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

    fun resetBackoff() {
        val prev = store.loadAttemptState()
        store.clearAttempts(seq = prev.seq)
    }

    private fun logResult(r: AuthRunResult) {
        val sink = log ?: return
        runCatching {
            val head = "[${r.trigger.wireName}]"
            val line = when (r.outcome) {
                RunOutcome.SUCCESS -> "$head 登录成功：${r.message}（code=${r.code}）"
                RunOutcome.RETRY_SCHEDULED -> "$head 登录失败：${r.message}（code=${r.code}）→ 重试第 ${r.attempt}/${policy.maxAttempts} 次，延迟 ${r.delaySeconds}s"
                RunOutcome.GIVE_UP -> "$head 登录放弃：连续失败 ${r.attempt} 次（上限 ${policy.maxAttempts} 次），code=${r.code}，不再重试"
                RunOutcome.SKIPPED_ZERO_REQUEST -> "$head 本次未认证：${r.message}（code=${r.code}），等待网络变化或周期检查"
                RunOutcome.WAITING -> "$head 等待：${r.message}（还需 ${r.delaySeconds}s）"
                RunOutcome.NO_CREDENTIAL -> "$head 未配置账号：${r.message}"
                RunOutcome.NO_PERMISSION -> "$head 权限缺失：${r.message}"
            }
            sink(line)
        }
    }

    fun maxAttempts(): Int = policy.maxAttempts
}
