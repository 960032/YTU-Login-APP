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
 * 真机 HTTP 引擎：`java.net.HttpURLConnection`（零第三方依赖）。
 *
 * 不使用 setInstanceFollowRedirects(true) 之外的重定向策略：SRun 门户在未认证时常以 302 跳到自身，
 * 跟随重定向与浏览器行为一致；跟随失败按 IOException 处理。
 */
class HttpUrlConnectionEngine(
    private val connectTimeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    private val readTimeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS
) : HttpEngine {

    override fun get(url: String, timeoutMs: Int): AuthResponse {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            instanceFollowRedirects = true
            connectTimeout = if (timeoutMs > 0) timeoutMs else connectTimeoutMs
            readTimeout = if (timeoutMs > 0) timeoutMs else readTimeoutMs
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

    private fun readAll(input: InputStream): String = input.readBytes().toString(Charsets.UTF_8)
}

/**
 * 真实的本机 IP 探测：与 portal 建立 TCP 连接后读取 `Socket.localAddress`，
 * **不硬编码**任何地址，也不依赖外部服务。
 */
class SocketLocalIpProbe : LocalIpProbe {
    override fun probe(host: String, port: Int, timeoutMs: Int): String? = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), if (timeoutMs > 0) timeoutMs else SrunProtocol.DEFAULT_TIMEOUT_MS)
            socket.localAddress?.hostAddress
        }
    } catch (e: IOException) {
        null
    } catch (e: SecurityException) {
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
