package top.ytu.srunautologin.flow

import java.io.IOException
import top.ytu.srunautologin.auth.AuthResponse
import top.ytu.srunautologin.auth.HttpEngine
import top.ytu.srunautologin.auth.JsonValue
import top.ytu.srunautologin.auth.Jsonp
import top.ytu.srunautologin.auth.SrunProtocol
import top.ytu.srunautologin.auth.SrunRequestBuilder
import top.ytu.srunautologin.auth.SrunResponseReader
import top.ytu.srunautologin.storage.KeyValueStore

enum class ProbeOutcome(val wireName: String) {
    NOT_SRUN("not_srun"),

    ALREADY_ONLINE("already_online"),

    NOT_LOGGED_IN("not_logged_in"),

    INDETERMINATE("indeterminate")
}

data class ProbeResult(
    val outcome: ProbeOutcome,
    val evidence: String,
    val httpStatus: Int = 0,
    val code: String? = null,
    val elapsedMs: Long = 0L
) {
    val isUncertain: Boolean get() = outcome == ProbeOutcome.INDETERMINATE
}

interface ProbePort {
    fun probe(portal: String, username: String, ip: String): ProbeResult

    companion object {
        val inactive: ProbePort = object : ProbePort {
            override fun probe(portal: String, username: String, ip: String): ProbeResult =
                ProbeResult(ProbeOutcome.INDETERMINATE, "未启用 SRun 探测（ProbePort.inactive）")
        }
    }
}

class SrunPortalProbe(
    private val engine: HttpEngine,
    private val timeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    socketFactory: top.ytu.srunautologin.auth.SocketFactoryProvider? = null,

    private val ipProbe: top.ytu.srunautologin.auth.LocalIpProbe? =
        top.ytu.srunautologin.auth.SocketLocalIpProbe(socketFactory)
) : ProbePort {

    override fun probe(portal: String, username: String, ip: String): ProbeResult {
        val started = System.currentTimeMillis()
        val host = SrunRequestBuilder.normalizePortal(portal)
        if (host.isEmpty()) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE, "门户地址为空，无法探测", 0, null,
                System.currentTimeMillis() - started
            )
        }
        val effectiveIp = resolveProbeIp(host, ip)
        val url = SrunRequestBuilder.buildUrl(
            host + SrunProtocol.PATH_CHALLENGE,
            listOf(
                "username" to username,
                "ip" to effectiveIp,
                SrunProtocol.CALLBACK_PARAM to SrunProtocol.CALLBACK_NAME
            )
        )
        val response: AuthResponse = try {
            engine.get(url, timeoutMs)
        } catch (e: IOException) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "探测请求失败（${e.javaClass.simpleName}）：请求详情已隐藏 → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        } catch (e: RuntimeException) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "探测请求异常（${e.javaClass.simpleName}）：请求详情已隐藏 → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        }
        return SrunProbeClassifier.classify(response.status, response.body)
            .copy(elapsedMs = System.currentTimeMillis() - started)
    }

    private fun resolveProbeIp(host: String, ip: String): String {
        if (ip.isNotBlank()) return ip
        val probe = ipProbe ?: return ip
        val probed = try {
            java.net.URI(host).let { uri ->
                probe.probe(uri.host.removePrefix("[").removeSuffix("]"),
                    if (uri.port > 0) uri.port else if (uri.scheme == "https") 443 else 80,
                    minOf(IP_PROBE_TIMEOUT_MS, timeoutMs))
            }
        } catch (e: IOException) {
            null
        } catch (e: RuntimeException) {
            null
        }
        return if (probed.isNullOrBlank()) ip else probed
    }

    companion object {
        const val HTTP_PORT: Int = 80

        const val IP_PROBE_TIMEOUT_MS: Int = 5_000
    }
}

class HttpProbeGate(
    private val engine: HttpEngine,
    private val ipProbe: top.ytu.srunautologin.auth.LocalIpProbe? = null
) : ProbePort {

    override fun probe(portal: String, username: String, ip: String): ProbeResult {
        val started = System.currentTimeMillis()
        val host = SrunRequestBuilder.normalizePortal(portal)
        if (host.isEmpty()) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE, "门户地址为空，无法探测", 0, null,
                System.currentTimeMillis() - started
            )
        }
        val url = SrunRequestBuilder.buildUrl(
            host + SrunProtocol.PATH_CHALLENGE,
            listOf(
                "username" to username,
                "ip" to ip,
                "callback" to SrunProtocol.CALLBACK_NAME
            )
        )
        val response: AuthResponse = try {
            engine.get(url, SrunProtocol.DEFAULT_TIMEOUT_MS)
        } catch (e: IOException) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "探测请求失败（${e.javaClass.simpleName}）：请求详情已隐藏 → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        } catch (e: RuntimeException) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "探测请求异常（${e.javaClass.simpleName}）：请求详情已隐藏 → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        }
        val result = SrunProbeClassifier.classify(response.status, response.body)
        return result.copy(elapsedMs = System.currentTimeMillis() - started)
    }
}

object SrunProbeClassifier {

    val ALREADY_ONLINE_PATTERN = Regex(
        "(?i)(already\\s*online|already\\s*log|已在线|已经在?线|已登录|已经登录|请勿重复登录|重复登录)"
    )

    fun isAlreadyOnline(vararg texts: String?): Boolean =
        texts.any { !it.isNullOrBlank() && ALREADY_ONLINE_PATTERN.containsMatchIn(it) }

    fun classify(httpStatus: Int, body: String): ProbeResult {
        if (httpStatus !in 200..299) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "HTTP $httpStatus（响应不是 SRun 的 JSONP）→ 无法判断是否 SRun",
                httpStatus
            )
        }
        val value = Jsonp.tryParse(body)
        val root = value as? JsonValue.Obj
            ?: return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "响应不是 JSONP/JSON 对象 → 无法判断是否 SRun",
                httpStatus
            )
        val error = SrunResponseReader.errorOf(root)
        if (error == null) {
            return ProbeResult(
                ProbeOutcome.NOT_SRUN,
                "JSON 中没有 SRun error 字段 → 判定为非 SRun 认证系统",
                httpStatus
            )
        }
        if (ALREADY_ONLINE_PATTERN.containsMatchIn(error)) {
            return ProbeResult(
                ProbeOutcome.ALREADY_ONLINE,
                "服务端报告已在线 → 无需登录",
                httpStatus, error
            )
        }
        if (error == SrunProtocol.OK) {
            val token = SrunResponseReader.challengeOf(root)
            if (token.isNullOrEmpty()) {
                return ProbeResult(
                    ProbeOutcome.INDETERMINATE,
                    "error=ok 但缺少 challenge 字段 → 响应形态异常",
                    httpStatus, error
                )
            }
            return ProbeResult(
                ProbeOutcome.NOT_LOGGED_IN,
                "是 SRun 系统，服务端返回 challenge（长度 ${token.length}）→ 未检测到已登录状态，将尝试认证",
                httpStatus, error
            )
        }
        return ProbeResult(ProbeOutcome.INDETERMINATE,
            "门户返回未识别的业务结果，将由认证步骤判断", httpStatus)

    }

}

data class ProbeAttemptState(
    val ssid: String,
    val attempts: Int = 0,
    val lastAtMillis: Long = 0L,
    val lastOutcome: String = ""
)

object ProbeRetryPolicy {

    const val RETRY_DELAY_MS: Long = 5 * 60_000L

    const val MAX_RETRIES: Int = 2

    const val MAX_ATTEMPTS: Int = MAX_RETRIES + 1

    const val KEY: String = "srun_probe_attempt_v1"

    data class Decision(val canRetry: Boolean, val reason: String)

    fun canProbe(state: ProbeAttemptState, nowMillis: Long): Decision {
        if (state.attempts >= MAX_ATTEMPTS) {
            return Decision(false, "已探测 ${state.attempts} 次（上限 $MAX_ATTEMPTS 次）→ 不再尝试")
        }
        if (state.attempts <= 0 || state.lastAtMillis <= 0L) {
            return Decision(true, "尚无探测记录 → 可以探测（第 ${state.attempts + 1} 次）")
        }
        val elapsed = nowMillis - state.lastAtMillis
        if (elapsed < RETRY_DELAY_MS) {
            return Decision(
                false,
                "距上次探测仅 ${elapsed / 1000}s，未到 ${RETRY_DELAY_MS / 60_000} 分钟间隔 → 本次不重复探测"
            )
        }
        return Decision(true, "距上次探测 ${elapsed / 1000}s → 可以重试（第 ${state.attempts + 1} 次）")
    }

    fun nextRetryAtMillis(nowMillis: Long): Long = nowMillis + RETRY_DELAY_MS

    fun describe(): String = "不确定时等 ${RETRY_DELAY_MS / 60_000} 分钟重试，最多 $MAX_RETRIES 次重试（共 $MAX_ATTEMPTS 次）"
}

class ProbeAttemptStore(private val kv: KeyValueStore) {

    fun load(): ProbeAttemptState? {
        val raw = kv.getString(ProbeRetryPolicy.KEY) ?: return null
        if (raw.isBlank()) return null
        val parts = raw.split("\t")
        val ssid = parts.getOrNull(0).orEmpty()
        val attempts = parts.getOrNull(1)?.toIntOrNull() ?: 0
        val last = parts.getOrNull(2)?.toLongOrNull() ?: 0L
        val outcome = parts.getOrNull(3).orEmpty()
        return ProbeAttemptState(ssid, attempts, last, outcome)
    }

    fun loadFor(ssid: String): ProbeAttemptState {
        val st = load() ?: return ProbeAttemptState(ssid)
        return if (st.ssid == ssid) st else ProbeAttemptState(ssid)
    }

    fun save(state: ProbeAttemptState) {
        kv.putString(
            ProbeRetryPolicy.KEY,
            listOf(state.ssid, state.attempts.toString(), state.lastAtMillis.toString(), state.lastOutcome)
                .joinToString("\t")
        )
    }

    fun record(ssid: String, atMillis: Long, outcome: ProbeOutcome, reset: Boolean = false): ProbeAttemptState {
        val prev = if (reset) ProbeAttemptState(ssid) else loadFor(ssid)
        val next = prev.copy(attempts = prev.attempts + 1, lastAtMillis = atMillis, lastOutcome = outcome.wireName)
        save(next)
        return next
    }

    fun reset(ssid: String) {
        save(ProbeAttemptState(ssid))
    }

    fun clear() {
        runCatching { kv.remove(ProbeRetryPolicy.KEY) }
    }
}
