package top.ytu.srunautologin.auth

import java.io.IOException
import java.io.InterruptedIOException
import java.net.URL
import top.ytu.srunautologin.log.AccountMask

class SrunAuthClient(
    private val engine: HttpEngine = HttpUrlConnectionEngine(),
    private val ipProbe: LocalIpProbe = SocketLocalIpProbe(),
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val mockFail: Boolean = false
) : AuthTransport {
    override fun execute(req: AuthRequest): AuthResult {
        val started = clock()
        fun elapsed() = (clock() - started).coerceAtLeast(0L)
        fun configuration(code: String, message: String) = AuthResult.failure(
            AuthFailure.CONFIG_MISSING, code, message, AuthStage.CONFIG, elapsed()
        )
        if (req.username.isBlank() || req.username.length > 512 || req.password.isEmpty() || req.password.length > 1024) {
            return configuration(AuthCodes.E_CONFIG, "请检查账号和密码")
        }
        if (!Regex("[0-9]{1,8}").matches(req.acId)) {
            return configuration(AuthCodes.E_CONFIG, "接入控制器编号无效")
        }
        val portal = PortalEndpoint.normalize(req.portal)
            ?: return configuration(AuthCodes.E_CONFIG, "门户地址无效，请填写完整的 HTTP 或 HTTPS 地址")
        if (PortalEndpoint.isCleartext(portal) && !req.allowInsecureHttp) {
            return configuration(AuthCodes.E_INSECURE_PORTAL, "此门户使用 HTTP，请先确认允许不加密的登录连接")
        }
        val request = req.copy(portal = portal)
        val deadline = RequestDeadline(if (req.timeoutMs > 0) req.timeoutMs else SrunProtocol.DEFAULT_TIMEOUT_MS)
        var stage = AuthStage.CHALLENGE
        var ip = req.ipOverride.trim()
        var ipSource = if (ip.isNotEmpty()) "override" else ""
        var token = ""
        fun failure(failure: AuthFailure, code: String, message: String) = AuthResult.failure(
            failure, code, message, stage, elapsed(), ipSource
        )
        fun safeMessage(message: String?): String? = message?.let {
            AccountMask.redact(it, listOf(req.username, req.password, token).filter(String::isNotEmpty))
                .replace(Regex("[\\p{Cntrl}]+"), " ").take(200)
        }
        fun safeCode(value: String?, fallback: String): String =
            value?.takeIf { Regex("(?:ok|E[0-9]{1,8}|E_[A-Z_]{1,30})").matches(it) } ?: fallback
        fun checkedBody(response: AuthResponse): JsonValue.Obj? =
            if (response.status in 200..299) Jsonp.tryParse(response.body) as? JsonValue.Obj else null
        try {
            val challenge = engine.get(SrunRequestBuilder.challengeUrl(request, ip), deadline.remainingMs())
            if (challenge.status !in 200..299) {
                return failure(AuthFailure.PORTAL_UNREACHABLE, AuthCodes.E_PORTAL, "门户返回 HTTP ${challenge.status}，尚未提交密码")
            }
            val root = checkedBody(challenge)
                ?: return failure(AuthFailure.PARSE_FAILED, AuthCodes.E_PARSE, "门户挑战响应不是有效的 JSON 或 JSONP 对象")
            if (!SrunResponseReader.isOk(root)) {
                val code = safeCode(SrunResponseReader.ecodeOf(root) ?: SrunResponseReader.errorOf(root), AuthCodes.E_CHALLENGE)
                return failure(AuthFailureClassifier.classify(code, stage), code,
                    safeMessage(SrunResponseReader.messageOf(root)) ?: "获取认证挑战失败")
            }
            token = SrunResponseReader.challengeOf(root).orEmpty()
            if (token.isBlank() || token.length > 512) {
                return failure(AuthFailure.PROTOCOL_ERROR, AuthCodes.E_CHALLENGE, "门户返回的认证挑战无效")
            }
            if (ip.isEmpty()) {
                val fromPortal = SrunResponseReader.clientIpOf(root)
                if (!fromPortal.isNullOrBlank() && fromPortal.length <= 45 && Regex("[0-9a-fA-F:.]+").matches(fromPortal)) {
                    ip = fromPortal
                    ipSource = "client_ip"
                } else {
                    val endpoint = URL(portal)
                    val port = if (endpoint.port > 0) endpoint.port else endpoint.defaultPort
                    ip = ipProbe.probe(endpoint.host, port, deadline.remainingMs()).orEmpty()
                    ipSource = if (ip.isEmpty()) "empty" else "local_probe"
                }
            }
            stage = AuthStage.LOGIN
            val login = engine.get(SrunRequestBuilder.portalUrl(request, token, ip, mockFail, clock()), deadline.remainingMs())
            if (login.status !in 200..299) {
                return failure(AuthFailure.PORTAL_UNREACHABLE, AuthCodes.E_PORTAL, "认证门户返回 HTTP ${login.status}")
            }
            stage = AuthStage.VERIFY
            val result = checkedBody(login)
                ?: return failure(AuthFailure.PARSE_FAILED, AuthCodes.E_PARSE, "登录响应不是有效的 JSON 或 JSONP 对象")
            if (SrunResponseReader.isOk(result)) {
                return AuthResult.success(stage, "认证成功", elapsed(), ipSource)
            }
            val code = safeCode(SrunResponseReader.ecodeOf(result) ?: SrunResponseReader.errorOf(result), AuthCodes.E_REJECTED)
            return failure(AuthFailureClassifier.classify(code, stage), code,
                safeMessage(SrunResponseReader.messageOf(result)) ?: "门户拒绝了认证请求")
        } catch (e: IOException) {
            val (code, message) = when (e) {
                is NetworkBindingException -> AuthCodes.E_WIFI_CHANGED to "目标 WiFi 已变化或不可用，本轮认证已停止"
                is ResponseTooLargeException -> AuthCodes.E_RESPONSE_LIMIT to "门户响应过大，已停止读取"
                is UnsafeRedirectException -> AuthCodes.E_REDIRECT to "门户发生重定向，请检查并保存最终门户地址"
                is javax.net.ssl.SSLException -> AuthCodes.E_TLS to "HTTPS 连接或证书验证失败，请检查门户地址和系统时间"
                is InterruptedIOException -> if (Thread.currentThread().isInterrupted) AuthCodes.E_CANCELLED to "认证任务已取消"
                    else AuthCodes.E_PORTAL to "门户连接超时"
                else -> AuthCodes.E_PORTAL to "无法连接认证门户（${e.javaClass.simpleName}）"
            }
            val category = if (code in setOf(AuthCodes.E_RESPONSE_LIMIT, AuthCodes.E_REDIRECT, AuthCodes.E_TLS))
                AuthFailure.PROTOCOL_ERROR else AuthFailure.PORTAL_UNREACHABLE
            return failure(category, code, message)
        }
    }
}
