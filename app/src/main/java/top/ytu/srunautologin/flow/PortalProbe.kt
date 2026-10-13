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

/**
 * ============================ 自动登录判断链的第 ②③ 段（logfix1 任务 C 段）============================
 *
 * 用户要求（原话）：
 *   「修改登录判断逻辑：检测到连接新wifi 时将其与已存储的网络比对，若符合则**验证该网络是否为
 *     SRun认证系统**，若为该系统则**检查网络是否已登录**，若未登录则执行自动登录。」
 *
 * 本文件把「是否 SRun 系统」与「是否已登录」做成**一次探测**（不多打 Portal）：
 *
 *   GET {portal}/cgi-bin/get_challenge?username=<真实用户名>&ip=<本机IP>&callback=callback
 *
 * 判定表（详见 [SrunProbeClassifier]；右侧「不确定」走 [ProbeOutcome.INDETERMINATE]）：
 *
 *  | 响应特征                                        | 结论                 |
 *  | ----------------------------------------------- | -------------------- |
 *  | `error` == "ok" 且含 `challenge` 字段            | 是 SRun + **未登录** |
 *  | `error` 含「已在线 / already online」类文案      | 是 SRun + **已登录** |
 *  | 有 `error` 字段但取值不认识（且不是 ok）         | 是 SRun + 未登录     |
 *  | JSONP/JSON 解析成功但没有 `error` 字段           | **非 SRun**          |
 *  | HTML / 404 / 超时 / 非 JSON                      | **不确定**           |
 *
 * 【为什么复用而不重写】URL 构造走 [SrunRequestBuilder.buildUrl]（与认证同一套编码）、
 * JSONP 剥壳走 [Jsonp]、字段读取走 [SrunResponseReader]，**加密/协议部分一行未改**。
 *
 * 【线程约束】本类会发网络请求（`HttpEngine.get` 是阻塞 IO），**必须在后台线程调用**；
 * 真机上主线程网络会抛 `NetworkOnMainThreadException`（AGENTS.md §7 已记录）。
 * 本类自身不创建线程，线程由调用方保证（认证链路天然在 worker 线程 / 后台线程上）。
 */

/** 一次探测的结论（四值，见文件头的判定表）。 */
enum class ProbeOutcome(val wireName: String) {
    /** **不是** SRun 认证系统（HTTP 200 但不是 SRun 的 JSONP、或 404、或 HTML）。 */
    NOT_SRUN("not_srun"),

    /** 是 SRun 认证系统，且当前**已登录**（服务端返回「已在线」类业务码）。 */
    ALREADY_ONLINE("already_online"),

    /** 是 SRun 认证系统，且当前**未登录** → 应该执行登录（第 ④ 段）。 */
    NOT_LOGGED_IN("not_logged_in"),

    /**
     * **不确定**（超时 / 网络异常 / 无响应 / 无 `error` 字段的异常形态）。
     *
     * 【probefix1 任务 B 段·口径变更】从「跳过并走 5 分钟重试」改为 **降级为继续认证**
     * （探测只是优化；探测本身不可靠时不应阻止真正的登录。若网络其实已在线，
     * 服务端回的「已在线」文案会被 [SrunProbeClassifier.isAlreadyOnline] 兜住）。
     */
    INDETERMINATE("indeterminate")
}

/** 一次探测的完整结果（结论 + 依据 + 脱敏后的诊断信息）。 */
data class ProbeResult(
    val outcome: ProbeOutcome,
    /** 判定依据（中文，可直接进日志；**不含密码**）。 */
    val evidence: String,
    val httpStatus: Int = 0,
    /** 服务端业务码原文（诊断用）。 */
    val code: String? = null,
    /** 耗时（毫秒）。 */
    val elapsedMs: Long = 0L
) {
    /** 是否需要走「5 分钟 / 最多 2 次重试」通道。 */
    val isUncertain: Boolean get() = outcome == ProbeOutcome.INDETERMINATE
}

/**
 * 探测端口：`flow` 模块只依赖这个接口，因此 [SrunPortalProbe] 之外还可以注入假实现做离线核对。
 */
interface ProbePort {
    /**
     * 探测一次。
     *
     * @param portal   门户地址（主机或带协议；内部用 [SrunRequestBuilder.normalizePortal] 归一化）
     * @param username **真实用户名**（协议要求，不能传脱敏值；它只出现在请求里，**不进日志**）
     * @param ip       本机 IP；为空时按空串发送（服务端响应里的 `client_ip` 仍可用于后续认证）
     */
    fun probe(portal: String, username: String, ip: String): ProbeResult

    companion object {
        /** 无感知实现：永远返回「不确定」——用于「不启用探测」的装配（老调用点/离线核对）。 */
        val inactive: ProbePort = object : ProbePort {
            override fun probe(portal: String, username: String, ip: String): ProbeResult =
                ProbeResult(ProbeOutcome.INDETERMINATE, "未启用 SRun 探测（ProbePort.inactive）")
        }
    }
}

/**
 * 真机探测实现：`get_challenge` 一次 GET + [SrunProbeClassifier] 判定。
 *
 * 【只读、无副作用】不登录、不改任何状态；失败一律收敛成 [ProbeOutcome.INDETERMINATE]（不抛异常）。
 * 【线程】阻塞 IO —— 调用方必须在后台线程（见文件头的线程约束）。
 */
class SrunPortalProbe(
    private val engine: HttpEngine,
    private val timeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    /**
     * 【probefix1 任务 C 段】本机 IP 探测（**复用既有能力**：`auth.LocalIpProbe`，
     * 与 [top.ytu.srunautologin.auth.SrunAuthClient] 是同一套实现）。
     *
     * 默认值就是真机实现 [top.ytu.srunautologin.auth.SocketLocalIpProbe]：真机装配点
     * （`work/AuthWorkWiring.kt`、`ui/MainActivity.kt`）只传 engine，因此修复必须落在默认值上，
     * 否则改了这里真机依旧发空 `ip=`。传 `null` = 完全不做 Socket 探测（纯离线可用的老行为）。
     *
     * 真机实测依据：认证请求（`ip=10.94.80.102`）33ms 返回；探测请求（`ip=` 空串）
     * TCP 连接超时 15s（SocketTimeoutException）。
     */
    private val ipProbe: top.ytu.srunautologin.auth.LocalIpProbe? =
        top.ytu.srunautologin.auth.SocketLocalIpProbe()
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
        // 【probefix1 任务 C 段】探测请求也带**真实本机 IP**：
        //   ip 已给出（非空）→ 直接用；
        //   ip 为空 → 用注入的 ipProbe 做一次 Socket 探测（connect 门户 80 端口 → 读 localAddress）；
        //   探不到（null / 异常）→ **降级为空串**（get_challenge 允许 ip 为空），不抛异常、不崩。
        val effectiveIp = resolveProbeIp(host, ip)
        // URL 构造完全复用 SrunRequestBuilder（与认证同一套编码顺序），不重写协议。
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
                "探测请求失败（${e.javaClass.simpleName}）：${e.message ?: "无 message"} → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        } catch (e: RuntimeException) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "探测请求异常（${e.javaClass.simpleName}）：${e.message ?: "无 message"} → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        }
        return SrunProbeClassifier.classify(response.status, response.body)
            .copy(elapsedMs = System.currentTimeMillis() - started)
    }

    /**
     * 【probefix1 任务 C 段】补齐本机 IP（**不硬编码任何地址**；与 `SrunAuthClient` 的
     * 「override > client_ip > 本机探测 > 空串」口径一致，这里只做「本机探测」这一档）。
     *
     * 探测失败一律返回原值（空串）→ 降级；本方法不抛异常，也不会让探测因取 IP 而失败。
     */
    private fun resolveProbeIp(host: String, ip: String): String {
        if (ip.isNotBlank()) return ip
        val probe = ipProbe ?: return ip
        val probed = try {
            probe.probe(hostOnly(host), HTTP_PORT, IP_PROBE_TIMEOUT_MS)
        } catch (e: IOException) {
            null
        } catch (e: RuntimeException) {
            null
        }
        return if (probed.isNullOrBlank()) ip else probed
    }

    /** 取纯主机名：`host:port` 去掉端口；`[ipv6]:port` 去掉方括号与端口（Socket 探测只需要主机名）。 */
    private fun hostOnly(host: String): String {
        val h = host.trim()
        if (h.startsWith("[")) return h.substringBefore("]").removePrefix("[")
        return if (h.count { it == ':' } == 1) h.substringBefore(':') else h
    }

    companion object {
        /** 门户 HTTP 端口（get_challenge 走 http）。 */
        const val HTTP_PORT: Int = 80

        /** 取本机 IP 的超时：5s（探测只是优化，不能先卡满 15s 再发请求）。 */
        const val IP_PROBE_TIMEOUT_MS: Int = 5_000
    }
}

/** HTTP 引擎 + 本机 IP 探测两件套（真机实现：`HttpUrlConnectionEngine` + `SocketLocalIpProbe`）。 */
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
        // ip 为空时不做 Socket 探测：get_challenge 允许 ip 为空，服务端响应里的 client_ip 可用于后续认证。
        // （少一次 Socket 连接 = 探测更快、更不容易被校园网网关限速。）
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
                "探测请求失败（${e.javaClass.simpleName}）：${e.message ?: "无 message"} → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        } catch (e: RuntimeException) {
            return ProbeResult(
                ProbeOutcome.INDETERMINATE,
                "探测请求异常（${e.javaClass.simpleName}）：${e.message ?: "无 message"} → 无法判断是否 SRun",
                0, null, System.currentTimeMillis() - started
            )
        }
        val result = SrunProbeClassifier.classify(response.status, response.body)
        return result.copy(elapsedMs = System.currentTimeMillis() - started)
    }
}

/** 纯逻辑判定器：把「HTTP 状态 + 响应体」映射成 [ProbeResult]（零网络、零 Android，可离线核对）。 */
object SrunProbeClassifier {

    /**
     * 「已在线」类业务码/文案的识别模式（大小写不敏感；真机实测过 `You are already online` 一类响应）。
     *
     * 【probefix1 任务 A 段】**单一真源**：探测路径（[classify]）与认证路径（`AuthFlow` 拿到
     * `srun_portal` 的失败响应之后）**共用同一个正则**，因此它由 `private` 改为可见
     * （Kotlin 默认即 public）。后续不得再复制第二份「已在线」正则。
     */
    val ALREADY_ONLINE_PATTERN = Regex(
        "(?i)(already\\s*online|already\\s*log|已在线|已经在?线|已登录|已经登录|请勿重复登录|重复登录)"
    )

    /**
     * 【probefix1 任务 A 段】**认证路径**的「已在线」判定：把服务端返回的 code 与 msg 一起送进来。
     *
     * 命中 = 服务端说「当前网络已经在线」→ 调用方（`AuthFlow`）按
     * [ProbeOutcome.ALREADY_ONLINE] 同义处理（跳过、不重试、不消耗退避预算）。
     *
     * **只匹配「已在线」语义**：`E2553 密码错误` 一类真正的拒绝文案不含这些关键词，
     * 因此不会被误判（判定表见 artifacts/probefix1/fix-report.md）。
     */
    fun isAlreadyOnline(vararg texts: String?): Boolean =
        texts.any { !it.isNullOrBlank() && ALREADY_ONLINE_PATTERN.containsMatchIn(it) }

    fun classify(httpStatus: Int, body: String): ProbeResult {
        if (httpStatus !in 200..299) {
            // 404/500 等：可能是其它网络的门户，也可能是校园网网关的异常页 → 不确定（走重试通道）
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
                "响应不是 JSONP/JSON 对象（前 120 字符）：${head(body)} → 无法判断是否 SRun",
                httpStatus
            )
        val error = SrunResponseReader.errorOf(root)
        if (error == null) {
            // 解析成功但**没有 error 字段** = 这不是 SRun 的 get_challenge 响应（其它门户/路由器登录页）
            return ProbeResult(
                ProbeOutcome.NOT_SRUN,
                "JSON 中没有 error 字段（字段：${root.keys().joinToString(",")}）→ 判定为非 SRun 认证系统",
                httpStatus
            )
        }
        if (ALREADY_ONLINE_PATTERN.containsMatchIn(error)) {
            return ProbeResult(
                ProbeOutcome.ALREADY_ONLINE,
                "是 SRun 系统，服务端业务码 error=\"$error\"（已在线）→ 无需登录",
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
                "是 SRun 系统，服务端返回 challenge（长度 ${token.length}）→ 当前未登录",
                httpStatus, error
            )
        }
        val message = SrunResponseReader.messageOf(root)
        // 有 error 字段但取值不认识：仍属 SRun（它认得我们的 get_challenge 请求），按「未登录」继续登录
        return ProbeResult(
            ProbeOutcome.NOT_LOGGED_IN,
            "是 SRun 系统（error=\"$error\"${if (message.isNullOrBlank()) "" else "，msg=$message"}）→ 按未登录继续",
            httpStatus, error
        )
    }

    private fun head(body: String): String =
        body.replace(Regex("\\s+"), " ").take(120)
}

/* ============================ 不确定时的重试状态（用户要求：等 5 分钟、最多 2 次） ============================ */

/**
 * 探测尝试的持久化状态（跨进程/跨重启）。
 *
 * @param ssid          这次记账对应的网络（**换网络即重新计数**）
 * @param attempts      已经发生的**探测**次数（1 = 第一次探测刚做完）
 * @param lastAtMillis  上一次探测的时刻
 * @param lastOutcome   上一次探测的结论（诊断用）
 */
data class ProbeAttemptState(
    val ssid: String,
    val attempts: Int = 0,
    val lastAtMillis: Long = 0L,
    val lastOutcome: String = ""
)

/**
 * 探测重试策略（**纯逻辑，不引用任何 Android API**，可离线核对）。
 *
 * 用户口径：探测**不确定**时 → 等 **5 分钟**重试，**最多 2 次重试**（即最多 3 次尝试）；
 * 全部失败 → 记日志不再尝试。
 *
 * 【probefix1 任务 B 段之后的分工（口径已变，变更说明逐字留档）】
 *  - 旧口径（logfix1）：探测不确定 → AuthFlow 返回 `E_PROBE_UNCERTAIN`（零认证请求）→ 本类排 5 分钟重试；
 *  - 新口径（probefix1·B）：探测不确定 → AuthFlow **降级为继续认证**，不再返回 `E_PROBE_UNCERTAIN`，
 *    也不为「不确定」写探测记账（只复位计数）。因此本类与 [ProbeAttemptStore]**不再有真机路径使用**，
 *    `work.ProbeRetryCoordinator.beforeProbe` 的闸门也不会再因「不确定次数用尽」拦住认证
 *    ——这正是任务 B 要修的行为（旧行为在真机上会把登录永久闸掉）。
 *  - 之所以**保留而不删除**：`work.ProbeRetryCoordinator` / `work.MorningAuthRuntime` 仍引用这些
 *    常量与存储（不在本次改动的写权限范围内）；保留一套不再触发的策略常量没有运行期代价。
 *  - 判断与理由见 artifacts/probefix1/fix-report.md（Bug B 一节）。
 */
object ProbeRetryPolicy {

    /** 两次探测之间的最小间隔：5 分钟（用户确认的决策）。 */
    const val RETRY_DELAY_MS: Long = 5 * 60_000L

    /** 最多重试次数：2（用户确认的决策）→ 探测最多 3 次。 */
    const val MAX_RETRIES: Int = 2

    /** 探测总次数上限 = 第一次 + 2 次重试。 */
    const val MAX_ATTEMPTS: Int = MAX_RETRIES + 1

    /** 记账键（专用，避免与认证退避计数/早上计数混用）。 */
    const val KEY: String = "srun_probe_attempt_v1"

    /** 决策：是否还能再来一次探测（含「再探」与「放弃」两种终止原因）。 */
    data class Decision(val canRetry: Boolean, val reason: String)

    /** 判定「现在能不能再探测一次」（在**发起探测之前**调用，避免多通道并发把预算打光）。 */
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

    /** 本次探测之后的下一次排期时刻（用于 AlarmManager / JobScheduler 的延迟计算）。 */
    fun nextRetryAtMillis(nowMillis: Long): Long = nowMillis + RETRY_DELAY_MS

    /** 人读描述（日志用）。 */
    fun describe(): String = "不确定时等 ${RETRY_DELAY_MS / 60_000} 分钟重试，最多 $MAX_RETRIES 次重试（共 $MAX_ATTEMPTS 次）"
}

/** 探测尝试状态的读写（复用既有 [KeyValueStore]，与认证/早上计数**不同的键**）。 */
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

    /**
     * 读取**针对某个 SSID** 的记账：SSID 不一致（换了网络）→ 返回全新状态（自动重新计数）。
     * 这也实现了用户要求的语义：「检测到连接新 wifi 时」重新走一遍判定链。
     */
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

    /** 记一次探测（次数 +1，写上次时刻与结论）。 */
    fun record(ssid: String, atMillis: Long, outcome: ProbeOutcome, reset: Boolean = false): ProbeAttemptState {
        val prev = if (reset) ProbeAttemptState(ssid) else loadFor(ssid)
        val next = prev.copy(attempts = prev.attempts + 1, lastAtMillis = atMillis, lastOutcome = outcome.wireName)
        save(next)
        return next
    }

    /** 复位（探测出确定结论 / 换网络 / 用户手动点「立即登录」时调用）。 */
    fun reset(ssid: String) {
        save(ProbeAttemptState(ssid))
    }

    fun clear() {
        runCatching { kv.remove(ProbeRetryPolicy.KEY) }
    }
}
