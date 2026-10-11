package top.ytu.srunautologin.work

import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.storage.KeyValueStore

/**
 * 后台认证的**状态回写**（基准卡 B5，模块 work，纯 JVM）。
 *
 * 契约（键名，用户 UI 与后台任务的唯一真相来源）：
 *  | Key（[KeyValueStore] 的 key）        | 值类型 | 含义                                              |
 *  |--------------------------------------|--------|---------------------------------------------------|
 *  | `srun_last_auth_status_v1`           | String | 最近一次**后台**认证结果（人类可读单行文本）      |
 *  | `srun_last_auth_status_code_v1`      | String | 最近一次后台认证结果的结构化 code（如 E_NETWORK）  |
 *  | `srun_last_auth_status_ok_v1`        | String | `"true"` / `"false"`                              |
 *  | `srun_last_auth_status_at_v1`        | String | 最近一次后台认证的完成时刻（epoch 毫秒，十进制）   |
 *  | `srun_auth_attempt_state_v1`         | String | 退避状态：`seq|attempts|lastEpochMs|firstEpochMs`  |
 *  | `srun_auth_foreground_status_v1`     | String | UI 前台「立即登录」写入的**同格式**单行文本（不与后台记录互相覆盖） |
 *
 * 为什么是这种形状：storage 层冻结的 [KeyValueStore] 只提供 String 读写
 * （见 artifacts/android-storage/storage-report.md:128-167），界面读取这些键即可显示
 * 「最近一次后台认证结果 + 时间 + 失败原因」，无需任何跨进程/文件依赖。
 *
 * 【不重复实现】本文件**不做任何 SSID 判断**——是否发起请求由 flow.AuthFlow 按 B8 决定。
 */
object AuthStatusKeys {
    const val STATUS_TEXT = "srun_last_auth_status_v1"
    const val STATUS_CODE = "srun_last_auth_status_code_v1"
    const val STATUS_OK = "srun_last_auth_status_ok_v1"
    const val STATUS_AT = "srun_last_auth_status_at_v1"
    const val ATTEMPT_STATE = "srun_auth_attempt_state_v1"
    const val FOREGROUND_STATUS_TEXT = "srun_auth_foreground_status_v1"

    /** 界面展示用：全部键名（顺序固定，供报告与自检逐字比对）。 */
    val all: List<String> = listOf(
        STATUS_TEXT, STATUS_CODE, STATUS_OK, STATUS_AT, ATTEMPT_STATE, FOREGROUND_STATUS_TEXT
    )
}

/** 后台触发来源（用于区分「开机」「网络变化」「周期保底」「用户手动」）。 */
enum class TriggerKind(val wireName: String) {
    BOOT("boot"),
    NETWORK("network"),
    PERIODIC("periodic"),
    MANUAL("manual")
}

/** 一次后台运行的结局（纯数据，供排期与状态回写使用）。 */
enum class RunOutcome(val wireName: String) {
    /** 认证成功。 */
    SUCCESS("success"),

    /** 按退避排期了下一次重试。 */
    RETRY_SCHEDULED("retry_scheduled"),

    /** 达到退避上限，停止重试。 */
    GIVE_UP("give_up"),

    /** B8 零请求跳过（未连目标 WiFi / 未绑定 / 读不到 SSID）→ 短延迟复检。 */
    SKIPPED_ZERO_REQUEST("skipped_zero_request"),

    /** 退避窗口未到 / 网络未就绪，本次只等待。 */
    WAITING("waiting"),

    /** 没有可用凭据（用户还没配置），不消耗重试次数。 */
    NO_CREDENTIAL("no_credential"),

    /**
     * 缺少读取 WiFi 的权限：页面读不到 SSID，无论重试多少次都会「读不到」。
     * 调度层据此**停止本次重试**（终态），避免每 30 秒空转一次打醒设备。
     */
    NO_PERMISSION("no_permission")
}

/**
 * 持久化的退避状态（`srun_auth_attempt_state_v1` 的解析结果）。
 *
 * 编码（一行、竖线分隔、向后兼容）：`seq|attempts|lastEpochMs|firstEpochMs|lastRequestEpochMs`
 *  - 只有 4 段时 [lastRequestAtMillis] 退化为 [lastAttemptAtMillis]（旧数据可读）。
 */
data class AttemptState(
    val seq: Long = 0L,
    val attempts: Int = 0,
    val lastAttemptAtMillis: Long = 0L,
    val firstAttemptAtMillis: Long = 0L,
    /** 上一次**真正发起过 HTTP 请求**的时刻；退避窗口只由它驱动。 */
    var lastRequestAtMillis: Long = 0L
) {
    /** 序列化为一行：`seq|attempts|lastEpochMs|firstEpochMs|lastRequestEpochMs`。 */
    fun encode(): String = "$seq|$attempts|$lastAttemptAtMillis|$firstAttemptAtMillis|$lastRequestAtMillis"

    /** 距离上次尝试的秒数；没有历史返回 null。 */
    fun elapsedSinceLastSeconds(now: Long): Long? =
        if (lastAttemptAtMillis <= 0L) null else ((now - lastAttemptAtMillis) / 1000L).coerceAtLeast(0L)

    companion object {
        /** 解析失败返回 null（损坏/旧格式视同「无历史」，不抛异常）。 */
        fun decode(raw: String?): AttemptState? {
            val s = raw?.trim().orEmpty()
            if (s.isEmpty()) return null
            val f = s.split('|')
            if (f.size != 4 && f.size != 5) return null
            val seq = f[0].toLongOrNull() ?: return null
            val attempts = f[1].toIntOrNull()?.takeIf { it >= 0 } ?: return null
            val last = f[2].toLongOrNull()?.takeIf { it >= 0 } ?: return null
            val first = f[3].toLongOrNull()?.takeIf { it >= 0 } ?: return null
            val lastRequest = if (f.size == 5) {
                f[4].toLongOrNull()?.takeIf { it >= 0 } ?: last
            } else {
                last // 旧格式（4 段）向后兼容
            }
            return AttemptState(seq, attempts, last, first, lastRequest)
        }
    }
}

/** 状态仓库：写读 [KeyValueStore]（真机为 SharedPreferences，见 platform 层）。 */
class AuthStatusStore(private val kv: KeyValueStore) {

    /* ------------------------------ 状态回写（B5） ------------------------------ */

    /** 写入一次结果：文本 + code + ok + 时间。`text` 必须是不含换行的可读单行。 */
    fun saveResult(
        text: String,
        code: String,
        ok: Boolean,
        atMillis: Long,
        key: String = AuthStatusKeys.STATUS_TEXT
    ) {
        val oneLine = text.replace('\n', ' ').replace('\r', ' ')
        kv.putString(key, oneLine)
        if (key == AuthStatusKeys.STATUS_TEXT) {
            kv.putString(AuthStatusKeys.STATUS_CODE, code)
            kv.putString(AuthStatusKeys.STATUS_OK, if (ok) "true" else "false")
            kv.putString(AuthStatusKeys.STATUS_AT, atMillis.toString())
        }
    }

    /** 读取最近一次（后台）结果的单行文本；没有记录返回 null。 */
    fun lastStatusText(): String? = kv.getString(AuthStatusKeys.STATUS_TEXT)?.takeIf { it.isNotBlank() }

    /** 读取最近一次（后台）结果的 code；没有记录返回 null。 */
    fun lastStatusCode(): String? = kv.getString(AuthStatusKeys.STATUS_CODE)?.takeIf { it.isNotBlank() }

    /** 读取最近一次（后台）结果是否成功；没有记录返回 null。 */
    fun lastStatusOk(): Boolean? = kv.getString(AuthStatusKeys.STATUS_OK)?.let { it == "true" }

    /** 读取最近一次（后台）结果的时刻毫秒；没有记录返回 null。 */
    fun lastStatusAtMillis(): Long? = kv.getString(AuthStatusKeys.STATUS_AT)?.toLongOrNull()

    /** 读取并解析退避状态。 */
    fun loadAttemptState(): AttemptState =
        AttemptState.decode(kv.getString(AuthStatusKeys.ATTEMPT_STATE)) ?: AttemptState()

    /** 写入退避状态。 */
    fun saveAttemptState(state: AttemptState) {
        kv.putString(AuthStatusKeys.ATTEMPT_STATE, state.encode())
    }

    /** 成功/用户重新配置后清零退避计数（seq 继续递增，便于审计「第几次运行」）。 */
    fun clearAttempts(seq: Long, atMillis: Long = 0L) {
        saveAttemptState(AttemptState(seq = seq, attempts = 0, lastAttemptAtMillis = atMillis, firstAttemptAtMillis = 0L))
    }

    /* --------------------- 一行式结果文本（后台/前台共用格式） --------------------- */

    companion object {
        /**
         * 生成状态行：`[后台:开机] 2026-10-11 14:20:33 失败（网络不可达）：... · E_NETWORK（尝试 3/5）`
         *
         * @param attempts 已消耗次数（0 表示本次没消耗）；[maxAttempts] 为上限，用于显示 `3/5`
         */
        fun formatLine(
            trigger: TriggerKind,
            atMillis: Long,
            ok: Boolean,
            code: String,
            message: String,
            failureName: String? = null,
            attempts: Int = 0,
            maxAttempts: Int = 0
        ): String {
            val head = if (ok) "成功" else "失败"
            val reason = if (ok) "" else "（${failureName ?: code}）"
            val suffix = if (attempts > 0 && maxAttempts > 0) "（尝试 $attempts/$maxAttempts）" else ""
            return "[后台:${trigger.wireName}] ${formatTime(atMillis)} $head$reason：$message" +
                if (ok) "" else " · $code$suffix"
        }

        /** 本地时间 `yyyy-MM-dd HH:mm:ss`（不依赖 java.time 的时区/格式配置）。 */
        fun formatTime(millis: Long): String {
            val cal = java.util.Calendar.getInstance()
            cal.timeInMillis = millis
            fun two(v: Int) = if (v < 10) "0$v" else "$v"
            return "${cal.get(java.util.Calendar.YEAR)}-${two(cal.get(java.util.Calendar.MONTH) + 1)}-" +
                "${two(cal.get(java.util.Calendar.DAY_OF_MONTH))} " +
                "${two(cal.get(java.util.Calendar.HOUR_OF_DAY))}:" +
                "${two(cal.get(java.util.Calendar.MINUTE))}:" +
                two(cal.get(java.util.Calendar.SECOND))
        }

        /** 从 AuthFlow 的 outcome 里取 code（Skipped 用 E_SKIP_*）。 */
        fun codeOf(outcome: AuthFlowOutcome): String = BackoffScheduler.codeOf(outcome)

        /** 从 AuthFlow 的 outcome 里取 UI 展示文本。 */
        fun messageOf(outcome: AuthFlowOutcome): String = when (outcome) {
            is AuthFlowOutcome.Done -> outcome.result.msg
            is AuthFlowOutcome.Skipped -> top.ytu.srunautologin.flow.AuthSkip.toResult(outcome).msg
        }

        /** 从 AuthFlow 的 outcome 里取结构化 [AuthResult]（Skipped 会合成为 skip 结果）。 */
        fun resultOf(outcome: AuthFlowOutcome): AuthResult = when (outcome) {
            is AuthFlowOutcome.Done -> outcome.result
            is AuthFlowOutcome.Skipped -> top.ytu.srunautologin.flow.AuthSkip.toResult(outcome)
        }
    }
}
