package top.ytu.srunautologin.auth

object SrunProtocol {
    const val N: Int = 200

    const val TYPE: Int = 1

    const val DOUBLE_STACK: Int = 0

    const val OS: String = "Windows"

    const val PATH_CHALLENGE: String = "/cgi-bin/get_challenge"

    const val PATH_PORTAL: String = "/cgi-bin/srun_portal"

    const val DEFAULT_TIMEOUT_MS: Int = 15_000

    const val OK: String = "ok"

    const val CALLBACK_PARAM: String = "callback"

    const val CALLBACK_NAME: String = "callback"
}

data class AuthRequest(
    val username: String,
    val password: String,
    val acId: String,
    val portal: String,
    val ipOverride: String = "",
    val timeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    val allowInsecureHttp: Boolean = false
) {
    override fun toString(): String =
        "AuthRequest(username=${top.ytu.srunautologin.log.AccountMask.maskAccount(username)}, password=***, acId=$acId, portal=${PortalEndpoint.normalize(portal) ?: "invalid"}, " +
            "ipOverride=$ipOverride, timeoutMs=$timeoutMs)"
}

data class AuthResult(
    val ok: Boolean,
    val code: String,
    val msg: String,
    val stage: String,
    val elapsedMs: Long,
    val failure: AuthFailure? = null,
    val ipSource: String = ""
) {
    companion object {
        fun success(stage: String, msg: String, elapsedMs: Long, ipSource: String): AuthResult =
            AuthResult(true, SrunProtocol.OK, msg, stage, elapsedMs, null, ipSource)

        fun failure(
            failure: AuthFailure,
            code: String,
            msg: String,
            stage: String,
            elapsedMs: Long,
            ipSource: String = ""
        ): AuthResult = AuthResult(false, code, msg, stage, elapsedMs, failure, ipSource)
    }
}

enum class AuthFailure(val displayName: String) {
    NETWORK_UNREACHABLE("网络不可达"),
    PORTAL_UNREACHABLE("门户不可达"),

    REJECTED("服务端拒绝（密码错误等）"),
    CONFIG_MISSING("配置缺失"),

    ALREADY_ONLINE("已在线，无需登录"),
    PARSE_FAILED("响应解析失败"),
    PROTOCOL_ERROR("协议异常"),
    UNKNOWN("未知错误")
}

object AuthStage {
    const val CONFIG = "config"
    const val CHALLENGE = "challenge"
    const val LOGIN = "login"
    const val VERIFY = "verify"
}

object AuthCodes {
    const val OK = "ok"
    const val E_CONFIG = "E_CONFIG"
    const val E_NETWORK = "E_NETWORK"
    const val E_PORTAL = "E_PORTAL"
    const val E_CHALLENGE = "E_CHALLENGE"
    const val E_PARSE = "E_PARSE"
    const val E_REJECTED = "E_REJECTED"
    const val E_UNKNOWN = "E_UNKNOWN"
    const val E_INSECURE_PORTAL = "E_INSECURE_PORTAL"
    const val E_WIFI_CHANGED = "E_WIFI_CHANGED"
    const val E_RESPONSE_LIMIT = "E_RESPONSE_LIMIT"
    const val E_REDIRECT = "E_REDIRECT"
    const val E_TLS = "E_TLS"
    const val E_CANCELLED = "E_CANCELLED"
}

data class AuthResponse(val status: Int, val body: String)

fun interface AuthTransport {
    fun execute(req: AuthRequest): AuthResult
}

object AuthFailureClassifier {

    fun classify(code: String, stage: String): AuthFailure = when (code) {
        AuthCodes.E_NETWORK -> AuthFailure.NETWORK_UNREACHABLE
        AuthCodes.E_PORTAL -> AuthFailure.PORTAL_UNREACHABLE
        AuthCodes.E_CONFIG, AuthCodes.E_INSECURE_PORTAL -> AuthFailure.CONFIG_MISSING
        AuthCodes.E_PARSE -> AuthFailure.PARSE_FAILED
        AuthCodes.E_TLS, AuthCodes.E_REDIRECT, AuthCodes.E_RESPONSE_LIMIT -> AuthFailure.PROTOCOL_ERROR
        AuthCodes.E_WIFI_CHANGED, AuthCodes.E_CANCELLED -> AuthFailure.NETWORK_UNREACHABLE
        AuthCodes.E_CHALLENGE -> AuthFailure.PROTOCOL_ERROR
        AuthResultStatus.CODE_ALREADY_ONLINE -> AuthFailure.ALREADY_ONLINE
        else -> if (stage == AuthStage.LOGIN || stage == AuthStage.VERIFY) {
            AuthFailure.REJECTED
        } else {
            AuthFailure.UNKNOWN
        }
    }
}
