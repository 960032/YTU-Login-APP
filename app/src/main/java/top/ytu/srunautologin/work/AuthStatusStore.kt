package top.ytu.srunautologin.work

import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.storage.KeyValueStore

object AuthStatusKeys {
    const val STATUS_TEXT = "srun_last_auth_status_v1"
    const val STATUS_CODE = "srun_last_auth_status_code_v1"
    const val STATUS_OK = "srun_last_auth_status_ok_v1"
    const val STATUS_AT = "srun_last_auth_status_at_v1"
    const val ATTEMPT_STATE = "srun_auth_attempt_state_v1"
    const val FOREGROUND_STATUS_TEXT = "srun_auth_foreground_status_v1"

    val all: List<String> = listOf(
        STATUS_TEXT, STATUS_CODE, STATUS_OK, STATUS_AT, ATTEMPT_STATE, FOREGROUND_STATUS_TEXT
    )
}

enum class TriggerKind(val wireName: String) {
    BOOT("boot"),
    NETWORK("network"),
    PERIODIC("periodic"),
    MANUAL("manual")
}

enum class RunOutcome(val wireName: String) {
    SUCCESS("success"),

    RETRY_SCHEDULED("retry_scheduled"),

    GIVE_UP("give_up"),

    SKIPPED_ZERO_REQUEST("skipped_zero_request"),

    WAITING("waiting"),

    NO_CREDENTIAL("no_credential"),

    NO_PERMISSION("no_permission")
}

data class AttemptState(
    val seq: Long = 0L,
    val attempts: Int = 0,
    val lastAttemptAtMillis: Long = 0L,
    val firstAttemptAtMillis: Long = 0L,
    var lastRequestAtMillis: Long = 0L
) {
    fun encode(): String = "$seq|$attempts|$lastAttemptAtMillis|$firstAttemptAtMillis|$lastRequestAtMillis"

    fun elapsedSinceLastSeconds(now: Long): Long? =
        if (lastAttemptAtMillis <= 0L) null else ((now - lastAttemptAtMillis) / 1000L).coerceAtLeast(0L)

    companion object {
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

class AuthStatusStore(private val kv: KeyValueStore) {

    fun saveResult(
        text: String,
        code: String,
        ok: Boolean,
        atMillis: Long,
        key: String = AuthStatusKeys.STATUS_TEXT
    ) {
        val oneLine = text.replace('\n', ' ').replace('\r', ' ')
        if (key == AuthStatusKeys.STATUS_TEXT) {
            kv.putAll(mapOf(key to oneLine, AuthStatusKeys.STATUS_CODE to code,
                AuthStatusKeys.STATUS_OK to ok.toString(), AuthStatusKeys.STATUS_AT to atMillis.toString()))
        } else kv.putString(key, oneLine)
    }

    private fun actionKey(ssid: String): String = "srun_user_action_" +
        java.security.MessageDigest.getInstance("SHA-256").digest(ssid.toByteArray(Charsets.UTF_8))
            .take(16).joinToString("") { "%02x".format(it.toInt() and 255) }

    fun userActionRequired(ssid: String? = null): Boolean =
        ssid != null && kv.getString(actionKey(ssid)) == "1"

    fun setUserActionRequired(required: Boolean, ssid: String? = null) {
        if (ssid == null) {
            if (!required) kv.keys().filter { it.startsWith("srun_user_action_") }.forEach(kv::remove)
        } else if (required) kv.putString(actionKey(ssid), "1") else kv.remove(actionKey(ssid))
    }

    fun lastStatusText(): String? = kv.getString(AuthStatusKeys.STATUS_TEXT)?.takeIf { it.isNotBlank() }

    fun lastStatusCode(): String? = kv.getString(AuthStatusKeys.STATUS_CODE)?.takeIf { it.isNotBlank() }

    fun lastStatusOk(): Boolean? = kv.getString(AuthStatusKeys.STATUS_OK)?.let { it == "true" }

    fun lastStatusAtMillis(): Long? = kv.getString(AuthStatusKeys.STATUS_AT)?.toLongOrNull()

    fun loadAttemptState(): AttemptState =
        AttemptState.decode(kv.getString(AuthStatusKeys.ATTEMPT_STATE)) ?: AttemptState()

    fun saveAttemptState(state: AttemptState) {
        kv.putString(AuthStatusKeys.ATTEMPT_STATE, state.encode())
    }

    fun clearAttempts(seq: Long, atMillis: Long = 0L) {
        saveAttemptState(AttemptState(seq = seq, attempts = 0, lastAttemptAtMillis = atMillis, firstAttemptAtMillis = 0L))
    }

    companion object {
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

        fun codeOf(outcome: AuthFlowOutcome): String = BackoffScheduler.codeOf(outcome)

        fun messageOf(outcome: AuthFlowOutcome): String = when (outcome) {
            is AuthFlowOutcome.Done -> outcome.result.msg
            is AuthFlowOutcome.Skipped -> top.ytu.srunautologin.flow.AuthSkip.toResult(outcome).msg
        }

        fun resultOf(outcome: AuthFlowOutcome): AuthResult = when (outcome) {
            is AuthFlowOutcome.Done -> outcome.result
            is AuthFlowOutcome.Skipped -> top.ytu.srunautologin.flow.AuthSkip.toResult(outcome)
        }
    }
}
