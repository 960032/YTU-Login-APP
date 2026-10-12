package top.ytu.srunautologin.work

import top.ytu.srunautologin.storage.KeyValueStore

/**
 * ============================ 早上自动登录：纯逻辑状态机（可离线核对）============================
 * 本文件**不引用任何 Android API**，只做时间/次数/决策这类可在 JVM 上判断的逻辑；
 * Android 侧（AlarmManager / 前台服务）在 [MorningAuthRuntime] 与 [MorningAuthForegroundService] 里。
 *
 * 【需求口径（用户原话）】凌晨 5:30 上电，6:00 添加自启动任务与登录检测；
 *   若「已连接网络匹配保存的账号密码 且 未处于登录状态」则自动登录；
 *   若没有连接，10 分钟后重试，最多尝试 6 次（到 7:00）。
 * 【已确认的裁决】首次 + 6 次重试 = 共 7 次尝试；6:00 首次，之后 6:10/6:20/6:30/6:40/6:50/7:00；
 *   7:00 之后当天不再尝试。
 * ============================================================================================
 */

/** 早上例程的时间/次数口径（时间用「当地当日分钟数」表达，避免时区/DST 依赖）。 */
object MorningAutoLogin {

    /** 首次时间 06:00 → 6*60。 */
    const val FIRST_MINUTE_OF_DAY: Int = 6 * 60

    /** 重试间隔 10 分钟。 */
    const val RETRY_INTERVAL_MINUTES: Int = 10

    /** **重试**次数上限（用户口径「最多尝试 6 次」指的是重试；加上首次共 7 次）。 */
    const val MAX_RETRY_AFTER_FIRST: Int = 6

    /** 当天总尝试次数上限 = 首次 + 6 次重试 = 7（用于「最后一次尝试」的兜底判断）。 */
    const val MAX_ATTEMPTS_PER_DAY: Int = MAX_RETRY_AFTER_FIRST + 1

    /** 当天尝试窗口结束时间 07:00 → 7*60（含 7:00 那一次；之后当天不再尝试）。 */
    const val WINDOW_END_MINUTE_OF_DAY: Int = 7 * 60

    /** 时间窗口（分钟）,用于界面/报告展示。 */
    const val WINDOW = "06:00 首次 → 每 10 分钟一次 → 07:00 最后一次，共 7 次"

    /** 兜底排期（无法精确调度时）：按「分钟」取整，保证最小间隔是整分钟数。 */
    fun fallbackIntervalMillis(): Long = RETRY_INTERVAL_MINUTES.coerceAtLeast(1) * 60_000L

    /** 当地当日零点毫秒（不依赖某项 API，时区取 JVM 默认时区）。 */
    fun localStartOfDay(atMillis: Long): Long {
        val zone = java.util.TimeZone.getDefault()
        val cal = java.util.Calendar.getInstance(zone)
        cal.timeInMillis = atMillis
        cal.set(java.util.Calendar.HOUR_OF_DAY, 0)
        cal.set(java.util.Calendar.MINUTE, 0)
        cal.set(java.util.Calendar.SECOND, 0)
        cal.set(java.util.Calendar.MILLISECOND, 0)
        return cal.timeInMillis
    }

    /** 当地当日分钟数（0..1439）。 */
    fun minuteOfDay(atMillis: Long): Int = ((atMillis - localStartOfDay(atMillis)) / 60_000L).toInt()

    /** 今天 06:00 对应的毫秒（已过也照样返回今天那个 06:00）。 */
    fun todayFirstMillis(atMillis: Long): Long =
        localStartOfDay(atMillis) + FIRST_MINUTE_OF_DAY * 60_000L

    /** 今天 07:00 对应的毫秒（尝试窗口上界）。 */
    fun todayWindowEndMillis(atMillis: Long): Long =
        localStartOfDay(atMillis) + WINDOW_END_MINUTE_OF_DAY * 60_000L

    /** 下一次 06:00：今天 06:00 还没到就取今天，否则取明天。 */
    fun nextFirstMillis(fromMillis: Long): Long {
        val today = todayFirstMillis(fromMillis)
        return if (fromMillis < today) today else today + 24 * 60 * 60 * 1000L
    }

    /** 下一次重试时刻 = 当前时刻 + 10 分钟。 */
    fun nextRetryMillis(fromMillis: Long): Long = fromMillis + RETRY_INTERVAL_MINUTES * 60_000L

    /** 给界面/日志用的 HH:mm。 */
    fun hhmm(atMillis: Long): String {
        val m = minuteOfDay(atMillis)
        return "%02d:%02d".format(m / 60, m % 60)
    }
}

/**
 * 早上的尝试状态（**跨进程死亡、跨重启持久化**；与界面/前台服务共享同一份键值存储）。
 *
 * @param dayMarker 当地当日零点毫秒 —— 每天 06:00 换一天就重置计数（用户要求「每天 06:00 重置计数」）
 * @param attempts  当天已经尝试过几次（决定还能不能再排一次重试）
 * @param lastAtMillis 最近一次尝试的时刻
 * @param lastCode  最近一次的结论码（排障用：E_SKIP_* / E_SUCCESS ...）
 */
data class MorningAttempts(
    val dayMarker: Long = 0L,
    val attempts: Int = 0,
    val lastAtMillis: Long = 0L,
    val lastCode: String = ""
) {
    fun encode(): String = "$dayMarker|$attempts|$lastAtMillis|$lastCode"

    /** 今天是否已经尝试过（用于「重启后同一天不重复首跑」）。 */
    fun attemptedToday(day: Long): Boolean = dayMarker == day && attempts > 0

    companion object {
        val EMPTY = MorningAttempts()

        fun decode(raw: String?): MorningAttempts {
            if (raw.isNullOrBlank()) return EMPTY
            val parts = raw.split('|')
            if (parts.isEmpty()) return EMPTY
            return MorningAttempts(
                dayMarker = parts.getOrNull(0)?.toLongOrNull() ?: 0L,
                attempts = parts.getOrNull(1)?.toIntOrNull() ?: 0,
                lastAtMillis = parts.getOrNull(2)?.toLongOrNull() ?: 0L,
                lastCode = parts.getOrNull(3).orEmpty()
            )
        }
    }
}

/** 一次尝试之后的下一步动作。 */
enum class MorningDecision {
    /** 认证成功 → 当天收工。 */
    STOP_SUCCESS,

    /** 还需要再试 → 安排 +10 分钟的下一次闹钟。 */
    RETRY,

    /** 到了 07:00 或次数用完 → 当天不再尝试，等明天 06:00。 */
    STOP_EXPIRED
}

/**
 * 状态机：[next] 是**唯一**决定「还要不要再试一次」的地方（纯函数，可离线核对）。
 *
 * 决策规则（按优先级）：
 *  1. 已过 07:00 → [MorningDecision.STOP_EXPIRED]（当天不再尝试）；
 *  2. 已尝试次数 >= 7 → [MorningDecision.STOP_EXPIRED]（6 次重试用完）；
 *  3. 认证成功（authOk）→ [MorningDecision.STOP_SUCCESS]；
 *  4. 其余（没连上匹配网络 / 未到登录条件 / 认证失败 / E_NETWORK / 超时）→ [MorningDecision.RETRY]。
 *
 * 说明：第 4 条**故意覆盖「已在线」以外的所有非成功码**。服务端对「已在线」会返回可识别的
 *      `You are already online` 一类响应，认证客户端会把它判为成功并停止重试；
 *      而 [authOk] 之外的失败**倾向于再试一次**，避免因为一次网络抖动就放弃当天。
 */
object MorningAutoLoginPolicy {

    fun next(
        attemptsMade: Int,
        nowMillis: Long,
        authOk: Boolean
    ): MorningDecision = when {
        nowMillis >= MorningAutoLogin.todayWindowEndMillis(nowMillis) -> MorningDecision.STOP_EXPIRED
        attemptsMade >= MorningAutoLogin.MAX_ATTEMPTS_PER_DAY -> MorningDecision.STOP_EXPIRED
        authOk -> MorningDecision.STOP_SUCCESS
        else -> MorningDecision.RETRY
    }
}

/** 尝试次数的持久化读写（键名集中在这里，避免多处写字面量）。 */
class MorningStateStore(private val kv: KeyValueStore) {

    /** 当天已尝试次数（读之前先按「今天」重置，保证跨重启/跨天正确）。 */
    fun loadToday(nowMillis: Long): MorningAttempts {
        val stored = MorningAttempts.decode(kv.getString(KEY_STATE))
        val day = MorningAutoLogin.localStartOfDay(nowMillis)
        return if (stored.dayMarker == day) stored else MorningAttempts(dayMarker = day)
    }

    /** 记一次尝试，并写回「今天的次数 +1」。 */
    fun recordAttempt(nowMillis: Long, code: String): MorningAttempts {
        val today = loadToday(nowMillis)
        val next = today.copy(attempts = today.attempts + 1, lastAtMillis = nowMillis, lastCode = code)
        save(next)
        return next
    }

    fun save(state: MorningAttempts) {
        kv.putString(KEY_STATE, state.encode())
    }

    fun clear() {
        kv.remove(KEY_STATE)
    }

    companion object {
        /** 键名前缀：与既有 AuthStatusStore 的键（srun_auth_*）不冲突，可在同一份键值存储里共存。 */
        const val KEY_STATE = "srun_morning_attempts_v1"

        /** 启停开关的持久化键（用户要求：启用后才执行后台任务）。 */
        const val KEY_ENABLED = "srun_morning_enabled_v1"

        /** 缺省值：**停用**（用户明确说「用户启用后才执行后台任务」）。 */
        const val DEFAULT_ENABLED = false
    }
}

/**
 * 把「今天还能不能试」的判断集中在一处（供 AlarmManager 侧与 JobScheduler 兜底侧共用）。
 *
 * 返回 [MorningDecision]；同时给出「是当天第一次」的判断，用于把状态从「昨天」翻页到「今天」。
 */
object MorningAutoLoginRuntime {

    /** 现在是否处于「06:00 起、07:00 止」的尝试窗口内（含两端）。 */
    fun inWindow(nowMillis: Long): Boolean {
        val m = MorningAutoLogin.minuteOfDay(nowMillis)
        return m >= MorningAutoLogin.FIRST_MINUTE_OF_DAY && m <= MorningAutoLogin.WINDOW_END_MINUTE_OF_DAY
    }
}
