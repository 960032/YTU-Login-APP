package top.ytu.srunautologin.auth

import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/**
 * 单次 HTTP GET 的执行缝：把 `java.net.HttpURLConnection` 挡在接口后面，
 * 使认证编排（[SrunAuthClient]）可以在 JVM 上用手写假 HTTP 引擎离线测试。
 *
 * 真机实现：[HttpUrlConnectionEngine]。
 */
interface HttpEngine {
    /** 发起一次 GET。网络异常一律抛 [IOException]（由上层分类为 E_NETWORK / E_PORTAL）。 */
    fun get(url: String, timeoutMs: Int): AuthResponse
}

/** 本机 IP 探测缝（不硬编码任何地址）。 */
interface LocalIpProbe {
    /** 返回本机在「与 host 建立连接」时使用的源地址；探测失败返回 null。 */
    fun probe(host: String, port: Int, timeoutMs: Int): String?
}

/**
 * 【netfix1 任务 A 段】连接工厂缝：由实现方决定「**用哪条网络**」打开这个 URL。
 *
 * 真机根因（「门户连接失败」）：手机同时具备 WiFi（校园网，未认证）+ 移动数据时，Android 认为该 WiFi
 * 「无互联网（captive portal）」→ **系统默认网络 = 移动数据**；而 `URL(url).openConnection()` 永远跟随
 * 系统默认网络，于是发往校园网**内网**门户（如 202.194.116.116:80）的连接被送上移动数据，必然超时
 * （真机日志：15008ms / SocketTimeoutException；同一地址偶尔 33ms 成功 = 那一刻默认网络恰好是 WiFi）。
 * 修复 = 注入一个「显式选中 WiFi 的 `Network` 再 openConnection」的实现
 * （真机实现：`platform/WifiFirstConnectionFactory`）。
 *
 * 契约：
 *  - 返回 null = 「实现方无法选定网络」→ 引擎**回退**到 `URL(url).openConnection()`（旧行为），绝不因此失败；
 *  - 实现**不得抛异常**（真机实现内部 catch 一切并返回 null）；
 *  - 本接口与实现位于 `auth` 包（纯 JVM）：**不得 import android**，否则离线核对无法编译。
 */
interface ConnectionFactory {
    fun open(url: URL): java.net.URLConnection?
}

/**
 * 真机 HTTP 引擎：`java.net.HttpURLConnection`（零第三方依赖）。
 *
 * 不使用 setInstanceFollowRedirects(true) 之外的重定向策略：SRun 门户在未认证时常以 302 跳到自身，
 * 跟随重定向与浏览器行为一致；跟随失败按 IOException 处理。
 *
 * 【netfix1 任务 A/B/C 段】新增四个**可选**参数（全部带默认值：既有调用点、离线核对与新参数合成构造均不受影响）：
 *  - [connectionFactory]：显式网络绑定（默认 null = 系统默认网络 = 旧行为）；
 *  - [retryCount] / [retryDelayMs] / [attemptTimeoutCapMs]：连接级重试（**只在 IOException 上重试**）；
 *  - [log]：诊断日志缝（`auth` 层不得 import `log/AppLog`，故用闭包注入；默认为丢弃）。
 */
class HttpUrlConnectionEngine(
    private val connectTimeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    private val readTimeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    /** 显式网络绑定（真机 = 选中 WiFi 的 Network）；null = 走系统默认网络（旧行为）。 */
    private val connectionFactory: ConnectionFactory? = null,
    /** 连接失败（[IOException]，含 SocketTimeoutException / ConnectException）的**重试**次数，不含首次尝试。 */
    private val retryCount: Int = DEFAULT_RETRY_COUNT,
    /** 两次尝试之间的短暂退避（不睡长：失败根因是 connect 超时/拒绝）。 */
    private val retryDelayMs: Long = DEFAULT_RETRY_DELAY_MS,
    /** **单次尝试**的 connect/read 超时上限（仅当 retryCount > 0 时生效），保证总耗时可控。 */
    private val attemptTimeoutCapMs: Int = DEFAULT_ATTEMPT_TIMEOUT_MS,
    /** 诊断日志缝（一行一条）。默认丢弃；真机装配点注入 `AppLog.record`。 */
    private val log: (String) -> Unit = {}
) : HttpEngine {

    override fun get(url: String, timeoutMs: Int): AuthResponse {
        val requested = if (timeoutMs > 0) timeoutMs else connectTimeoutMs
        // 单次尝试超时：有重试时受 attemptTimeoutCapMs 约束（总耗时可控）；无重试时严格保持旧语义。
        val attemptTimeoutMs = if (retryCount > 0) minOf(requested, attemptTimeoutCapMs) else requested
        val attempts = retryCount.coerceAtLeast(0) + 1
        var lastError: IOException? = null
        for (attempt in 0 until attempts) {
            try {
                return attemptGet(url, attemptTimeoutMs)
            } catch (e: IOException) {
                // 只有 IOException 会走到这里：HTTP 4xx/5xx 在 attemptGet 里已作为响应返回，不重试。
                lastError = e
                log(
                    "HTTP 连接失败 attempt=${attempt + 1}/$attempts host=${safeHost(url)}" +
                        " 绑定=${if (connectionFactory != null) "WiFi优先" else "系统默认"}" +
                        " 单次超时=${attemptTimeoutMs}ms 异常=${e.javaClass.name}" +
                        " 本地地址=${localAddrOf(e)} 消息=${safeMessage(e)}"
                )
                if (attempt + 1 < attempts) {
                    // 本方法只在后台线程被调用（JobService / 「立即登录」线程 / 探测线程），sleep 可接受。
                    try {
                        Thread.sleep(retryDelayMs)
                    } catch (ie: InterruptedException) {
                        Thread.currentThread().interrupt() // 恢复中断标记，再按失败上抛（上层分类逻辑不变）
                        throw e
                    }
                }
            }
        }
        val finalError = lastError ?: IOException("连接失败（未知原因）")
        log(
            "HTTP 连接最终失败 attempts=$attempts host=${safeHost(url)}" +
                " 异常=${finalError.javaClass.name} 消息=${safeMessage(finalError)}"
        )
        throw finalError
    }

    /** 单次尝试：**HTTP 响应（含 4xx/5xx）都算成功返回**，只有 IOException 抛出、由 [get] 决定是否重试。 */
    private fun attemptGet(url: String, attemptTimeoutMs: Int): AuthResponse {
        val target = URL(url)
        // 【A 段核心】先让连接工厂显式选网；null（或工厂违约抛异常）→ 回退系统默认网络，保证不比旧版更差。
        val opened: java.net.URLConnection? = try {
            connectionFactory?.open(target)
        } catch (t: Throwable) {
            log("连接工厂异常，回退系统默认网络：${t.javaClass.name} 消息=${safeMessage(t)}")
            null
        }
        val conn = if (opened is HttpURLConnection) {
            opened
        } else {
            target.openConnection() as HttpURLConnection
        }
        conn.apply {
            requestMethod = "GET"
            instanceFollowRedirects = true
            connectTimeout = attemptTimeoutMs
            // 读超时同样收紧到单次预算内（旧默认 15s 在 3 次尝试下会拖到 45s）。
            readTimeout = if (readTimeoutMs > 0) minOf(readTimeoutMs, attemptTimeoutMs) else attemptTimeoutMs
            setRequestProperty("Accept", "application/javascript, application/json, text/plain, */*")
            setRequestProperty("User-Agent", "SrunAutoLogin-Android/0.1")
        }
        try {
            val status = conn.responseCode
            val stream: InputStream? = if (status in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.use { readAll(it) } ?: ""
            return AuthResponse(status, body)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * 只取 `host[:port]`：**绝不记录 query 串**（`get_challenge` 的 query 里带 username），
     * 保证日志零账号/零密码泄漏。
     */
    private fun safeHost(url: String): String = try {
        val u = URL(url)
        if (u.port > 0) "${u.host}:${u.port}" else u.host
    } catch (t: Throwable) {
        "?"
    }

    /** 异常消息单行化 + 截断（日志一行一条，防止异常消息里的换行污染日志）。 */
    private fun safeMessage(t: Throwable): String =
        (t.message ?: "").replace('\n', ' ').replace('\r', ' ').take(300)

    /**
     * 本地 socket 地址：直接取自 JDK 的连接失败消息（真机形如
     * `failed to connect to /202.194.116.116 (port 80) from /10.94.80.102 (port 58872)`），
     * **不额外发起任何连接**（零额外开销、零额外超时）。取不到记「未知」。
     */
    private fun localAddrOf(t: Throwable): String =
        LOCAL_ADDR.find(t.message ?: "")?.value ?: "未知"

    companion object {
        /** 默认重试次数（不含首次尝试）：2 → 最多 3 次尝试。 */
        const val DEFAULT_RETRY_COUNT: Int = 2

        /** 默认重试间隔：500ms（短暂退避；根因是 connect 超时/拒绝，睡长没有收益）。 */
        const val DEFAULT_RETRY_DELAY_MS: Long = 500L

        /**
         * 默认**单次尝试**超时上限：7s。
         *
         * 取舍理由：旧行为单次 15s；若沿用 15s，2 次重试的最坏耗时 = 15×3 + 0.5×2 = 46s
         * （用户点「立即登录」后 46 秒无任何响应，不可接受）。压到 7s 后最坏 = 7×3 + 0.5×2 ≈ 22s，
         * 与原来单次 15s **同量级**，但给了瞬时抖动 3 次机会。校园网内网门户 RTT 极低
         * （真机成功案例 33ms），7s 足以区分「需要重试的瞬时失败」与「完全不通」。
         */
        const val DEFAULT_ATTEMPT_TIMEOUT_MS: Int = 7_000

        /** 从失败消息里提取本地地址的固定片段：`from /ip (port n)`。 */
        private val LOCAL_ADDR = Regex("from\\s+/[0-9.]+\\s*\\(port \\d+\\)")
    }

    private fun readAll(input: InputStream): String = input.readBytes().toString(Charsets.UTF_8)
}

/**
 * 【onlinefix1 任务 B 段】Socket 创建缝：由实现方决定「**用哪条网络**」建这个 TCP 连接。
 *
 * **为什么需要它**：[netfix1]（`platform/WifiFirstConnectionFactory`）只给 **HTTP 引擎**绑定了
 * WiFi 网络，而 [SocketLocalIpProbe] 用的是裸 `Socket()` → 走**系统默认网络**。手机同时具备
 * WiFi（校园网，未认证）+ 移动数据时，Android 判定该 WiFi「无互联网（captive portal）」→
 * 默认网络 = 移动数据 → 探测拿到的 `localAddress` 是移动数据侧地址（或根本连不通门户）→
 * 传给门户的 `ip` 参数不准（真机日志里认证请求带的是 WiFi 地址 `10.94.80.102`）。
 *
 * **纯逻辑层不得 import android**：本接口是纯 JVM 抽象（只用 `java.net.Socket`），Android 实现
 * 放 `platform/WifiSocketFactoryProvider`（复用 `WifiFirstConnectionFactory.selectedWifiNetwork()`）。
 */
interface SocketFactoryProvider {
    /**
     * 在「指定的网络」上创建一个尚未连接的 [Socket]（调用方负责 connect 与关闭）。
     *
     * **绝不抛异常**：拿不到目标网络 / 建 socket 失败一律返回 `null` → 由 [SocketLocalIpProbe]
     * 回退到旧行为（系统默认网络），修复不允许把「IP 不准」变成「探测崩溃」。
     */
    fun createSocket(host: String, port: Int, timeoutMs: Int): Socket?
}

/**
 * 真实的本机 IP 探测：与 portal 建立 TCP 连接后读取 `Socket.localAddress`，
 * **不硬编码**任何地址，也不依赖外部服务。
 *
 * 【onlinefix1 任务 B 段】新增**可选**注入点 [socketFactory]（**带默认值 = 旧行为**，
 * 构造签名向后兼容：既有 `SocketLocalIpProbe()` 调用点的字节码不变）。传 null（默认）=
 * 裸 `Socket()` 走系统默认网络，与本段改造前**逐字节等价**。
 */
class SocketLocalIpProbe(
    private val socketFactory: SocketFactoryProvider? = null
) : LocalIpProbe {

    override fun probe(host: String, port: Int, timeoutMs: Int): String? {
        val timeout = if (timeoutMs > 0) timeoutMs else SrunProtocol.DEFAULT_TIMEOUT_MS
        // ① 先试「绑定网络的 socket」（真机 = WiFi）；取不到网络/建不出来 → 返回 null。
        if (socketFactory != null) {
            probeOnce(host, port, timeout, bound = true)?.let { return it }
        }
        // ② 回退：系统默认网络（旧行为，**永不抛异常**）。
        return probeOnce(host, port, timeout, bound = false)
    }

    /**
     * 一次探测。
     *
     * @param bound `false` = 系统默认网络（裸 `Socket()`，旧行为，**永远可用**）；
     *              `true`  = 通过 [socketFactory] 在选定网络（真机 = WiFi）上建 socket。
     * **本方法不抛异常**：任何异常（含 SDK 差异导致的 `SecurityException`、工厂返回 null、
     * connect 失败、DNS 失败）一律返回 null。
     */
    private fun probeOnce(host: String, port: Int, timeout: Int, bound: Boolean): String? = try {
        val socket: Socket? = if (bound) socketFactory?.createSocket(host, port, timeout) else Socket()
        socket?.use {
            it.connect(InetSocketAddress(host, port), timeout)
            it.localAddress?.hostAddress
        }
    } catch (e: IOException) {
        null
    } catch (e: SecurityException) {
        null
    } catch (t: Throwable) {
        // 兜底：SDK 差异（如 Network.getSocketFactory 在个别实现上抛其它异常类型）也不能把探测带崩
        null
    }
}

/**
 * 认证客户端：两步 HTTP GET + JSONP 的业务实现。
 *
 * 成功判定：**只认服务端 srun_portal 响应的业务码 error == "ok"**，HTTP 200 不作为成功依据。
 * 本类不抛异常：一切失败都落成 [AuthResult]（failure 分类见 [AuthFailureClassifier]）。
 */
class SrunAuthClient(
    private val engine: HttpEngine = HttpUrlConnectionEngine(),
    private val ipProbe: LocalIpProbe = SocketLocalIpProbe(),
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val mockFail: Boolean = false
) : AuthTransport {

    override fun execute(req: AuthRequest): AuthResult {
        val started = clock()
        fun elapsed(): Long = (clock() - started).coerceAtLeast(0L)

        // 阶段 0：配置校验（配置缺失 → E_CONFIG，不发出任何请求）
        if (req.username.isBlank()) {
            return AuthResult.failure(
                AuthFailure.CONFIG_MISSING, AuthCodes.E_CONFIG, "用户名为空，未发起任何请求",
                AuthStage.CONFIG, elapsed()
            )
        }
        if (req.acId != "5") {
            return AuthResult.failure(
                AuthFailure.CONFIG_MISSING, AuthCodes.E_CONFIG, "acId 已被裁决为字符串 \"5\"，实际为 \"${req.acId}\"",
                AuthStage.CONFIG, elapsed()
            )
        }
        val portal = SrunRequestBuilder.normalizePortal(req.portal)
        if (portal.isEmpty()) {
            return AuthResult.failure(
                AuthFailure.CONFIG_MISSING, AuthCodes.E_CONFIG, "门户地址为空，未发起任何请求",
                AuthStage.CONFIG, elapsed()
            )
        }

        // 阶段 0.5：ip 取值（仅当 ipOverride 为空时才探测，避免多余请求）
        var ip: String = req.ipOverride.trim()
        var ipSource = if (ip.isNotEmpty()) "override" else ""

        // 阶段 1：get_challenge
        val challengeUrl = SrunRequestBuilder.challengeUrl(req, ip)
        val challengeRaw: AuthResponse = try {
            engine.get(challengeUrl, req.timeoutMs)
        } catch (e: IOException) {
            return AuthResult.failure(
                AuthFailure.PORTAL_UNREACHABLE, AuthCodes.E_PORTAL,
                "无法连接门户（$portal）：${e.message ?: e::class.java.simpleName}",
                AuthStage.CHALLENGE, elapsed(), ipSource
            )
        }

        val challengeValue = Jsonp.tryParse(challengeRaw.body) ?: return AuthResult.failure(
            AuthFailure.PARSE_FAILED, AuthCodes.E_PARSE,
            "get_challenge 响应不是 JSONP/JSON（前 200 字符）：${head(challengeRaw.body)}",
            AuthStage.CHALLENGE, elapsed(), ipSource
        )
        val challengeRoot = challengeValue as? JsonValue.Obj ?: return AuthResult.failure(
            AuthFailure.PARSE_FAILED, AuthCodes.E_PARSE, "get_challenge 响应不是 JSON 对象",
            AuthStage.CHALLENGE, elapsed(), ipSource
        )

        if (!SrunResponseReader.isOk(challengeRoot)) {
            val code = SrunResponseReader.ecodeOf(challengeRoot) ?: SrunResponseReader.errorOf(challengeRoot) ?: AuthCodes.E_CHALLENGE
            return AuthResult.failure(
                AuthFailureClassifier.classify(code, AuthStage.CHALLENGE), code,
                SrunResponseReader.messageOf(challengeRoot) ?: "get_challenge 失败",
                AuthStage.CHALLENGE, elapsed(), ipSource
            )
        }
        val token = SrunResponseReader.challengeOf(challengeRoot) ?: return AuthResult.failure(
            AuthFailure.PROTOCOL_ERROR, AuthCodes.E_CHALLENGE, "get_challenge 响应缺少 challenge 字段",
            AuthStage.CHALLENGE, elapsed(), ipSource
        )

        // ip 优先级（本任务裁决）：ipOverride > 响应里的 client_ip > 本机探测 > 空串
        if (ip.isEmpty()) {
            val clientIp = SrunResponseReader.clientIpOf(challengeRoot)
            if (clientIp != null) {
                ip = clientIp
                ipSource = "client_ip"
            } else {
                val probed = ipProbe.probe(hostOf(portal), DEFAULT_HTTP_PORT, req.timeoutMs)
                if (probed != null && probed.isNotEmpty()) {
                    ip = probed
                    ipSource = "local_probe"
                } else {
                    ipSource = "empty"
                }
            }
        }

        // 阶段 2：srun_portal(action=login)
        val loginUrl = SrunRequestBuilder.portalUrl(req, token, ip, mockFail, clock())
        val loginRaw: AuthResponse = try {
            engine.get(loginUrl, req.timeoutMs)
        } catch (e: IOException) {
            return AuthResult.failure(
                AuthFailure.PORTAL_UNREACHABLE, AuthCodes.E_PORTAL,
                "无法连接门户（$portal）：${e.message ?: e::class.java.simpleName}",
                AuthStage.LOGIN, elapsed(), ipSource
            )
        }

        val loginValue = Jsonp.tryParse(loginRaw.body) ?: return AuthResult.failure(
            AuthFailure.PARSE_FAILED, AuthCodes.E_PARSE,
            "srun_portal 响应不是 JSONP/JSON（前 200 字符）：${head(loginRaw.body)}",
            AuthStage.VERIFY, elapsed(), ipSource
        )
        val loginRoot = loginValue as? JsonValue.Obj ?: return AuthResult.failure(
            AuthFailure.PARSE_FAILED, AuthCodes.E_PARSE, "srun_portal 响应不是 JSON 对象",
            AuthStage.VERIFY, elapsed(), ipSource
        )

        // 成功判定：只认业务码 error == "ok"
        if (SrunResponseReader.isOk(loginRoot)) {
            val extra = SrunResponseReader.messageOf(loginRoot)
            return AuthResult.success(
                AuthStage.VERIFY,
                if (extra.isNullOrEmpty()) "认证成功" else "认证成功：$extra",
                elapsed(), ipSource
            )
        }

        val code = SrunResponseReader.ecodeOf(loginRoot)
            ?: SrunResponseReader.errorOf(loginRoot)
            ?: AuthCodes.E_REJECTED
        return AuthResult.failure(
            AuthFailureClassifier.classify(code, AuthStage.LOGIN), code,
            SrunResponseReader.messageOf(loginRoot) ?: "认证失败（服务端未返回 ok）",
            AuthStage.LOGIN, elapsed(), ipSource
        )
    }

    private fun hostOf(portalUrl: String): String = try {
        URL(portalUrl).host ?: ""
    } catch (e: Exception) {
        ""
    }

    private fun head(body: String): String =
        body.replace(Regex("\\s+"), " ").take(200)
}

/** Socket 探测默认端口（http）。不硬编码任何主机地址。 */
private const val DEFAULT_HTTP_PORT = 80
