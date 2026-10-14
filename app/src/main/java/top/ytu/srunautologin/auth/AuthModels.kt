package top.ytu.srunautologin.auth

/**
 * 认证客户端的数据模型与接口（纯 JVM，不引用任何 Android API）。
 *
 * 设计约束：
 *  - 本文件所在的 auth 包必须能在无 Android SDK 的机器上编译与测试（见 jvm-check-client 模块）；
 *  - 密码学一律走已冻结的 [top.ytu.srunautologin.crypto.SrunCrypto]，本包不实现任何哈希/编码算法。
 */

/** 认证协议常量，逐字对齐参考实现 artifacts/srun-impl/srun-login.js。 */
object SrunProtocol {
    /** 协议常量 n（srun-login.js 顶部 N）。 */
    const val N: Int = 200

    /** 协议常量 type。 */
    const val TYPE: Int = 1

    /** 协议常量 double_stack。 */
    const val DOUBLE_STACK: Int = 0

    /** 登录方式客户端标识（os / name 两个字段）。 */
    const val OS: String = "Windows"

    /** get_challenge 路径。 */
    const val PATH_CHALLENGE: String = "/cgi-bin/get_challenge"

    /** srun_portal 路径。 */
    const val PATH_PORTAL: String = "/cgi-bin/srun_portal"

    /** 默认连接/读取超时（毫秒）。 */
    const val DEFAULT_TIMEOUT_MS: Int = 15_000

    /** 业务成功码：srun_portal 响应的 error 字段必须等于它。 */
    const val OK: String = "ok"

    /** 返回 JSONP 的 callback 参数名（与参考实现一致：callback=<name>）。 */
    const val CALLBACK_PARAM: String = "callback"

    /** JSONP 回调函数名（与参考实现 jsonpCb 同值）。 */
    const val CALLBACK_NAME: String = "callback"
}

/**
 * 一次认证请求所需的全部输入。
 *
 * @param username  完整用户名（可含运营商域名后缀，如 &lt;学号&gt;@ytu）
 * @param password  明文密码（只在内存中；不得写入任何日志/证据文件）
 * @param acId      **一律传字符串 "5"**（已裁决，与 Portal 前端 acid: data.ac_id 一致）
 * @param portal    门户地址或主机（如 10.0.0.1 或 http://10.0.0.1）；不带协议时按 http 处理
 * @param ipOverride 非空时直接使用该 ip，跳过客户端 IP 探测（证据 A-1：#user_ip 隐藏域由服务端渲染）
 */
data class AuthRequest(
    val username: String,
    val password: String,
    val acId: String,
    val portal: String,
    val ipOverride: String = "",
    val timeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS
) {
    /** 日志安全表示：绝不包含 password。 */
    override fun toString(): String =
        "AuthRequest(username=$username, password=***, acId=$acId, portal=$portal, " +
            "ipOverride=$ipOverride, timeoutMs=$timeoutMs)"
}

/**
 * 认证对外结果结构（契约，被后续任务复用）。
 *
 * @param ok        是否成功。**只由服务端 srun_portal 响应的业务码 error == "ok" 决定，HTTP 200 不作数。**
 * @param code      机器可读码：成功为 "ok"，失败为 E_* 或服务端 ecode
 * @param msg       人读信息（中文）
 * @param stage     失败/成功所处的阶段
 * @param elapsedMs 本次认证耗时（毫秒）
 * @param failure   失败分类（成功时为 null）
 * @param ipSource  ip 字段的来源（诊断用）：client_ip / local_probe / override / empty
 */
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

/** 错误分类：网络不可达 / Portal 不可达 / 业务拒绝 / 配置缺失 / 解析失败 / 协议异常。 */
enum class AuthFailure(val displayName: String) {
    NETWORK_UNREACHABLE("网络不可达"),
    PORTAL_UNREACHABLE("门户不可达"),

    /**
     * 【probefix1 任务 A 段】**真正的**服务端拒绝（密码错误 = `E2553` 一类）。
     *
     * 注意：「已在线」**不是**拒绝。服务端对已登录的网络再登录会回
     * `E2620 You are already online.`，该响应由 `flow.AuthFlow` 在走到本分类器**之前**
     * 就识别为「已在线」并跳过登录（判定入口 `flow.SrunProbeClassifier.isAlreadyOnline`，
     * 与探测路径共用同一份正则），因此**不会**落到本分类，也不消耗退避预算。
     * 判定表见 artifacts/probefix1/fix-report.md（Bug A 一节）。
     */
    REJECTED("服务端拒绝（密码错误等）"),
    CONFIG_MISSING("配置缺失"),

    /**
     * 【onlinefix1 任务 A 段】**目标已达成**：当前网络已在线，无需重复登录。
     *
     * 与其它取值语义相反 —— 它不是「错误」，而是「本次认证的目标本来就已满足」，因此它的
     * **displayName 不含「失败」二字**，UI 侧按成功语义展示（`ui/ConfigViewModel.kt` 与
     * `ui/MainActivity.kt` 统一用 `AuthResultStatus.isAlreadyOnline` 判定，不各写一份 `when`）。
     *
     * 来源码 = `E_SKIP_ALREADY_ONLINE`（= `flow.AuthSkipReason.ALREADY_ONLINE.code`；服务端对已登录
     * 的网络再登录回 `E2620 You are already online.`）。此前没有该取值 → 落
     * [AuthFailureClassifier] 的 `else` 分支 → 被误报为 [CONFIG_MISSING]（「配置缺失」），
     * 真机日志逐字为：`「立即登录」结果=未登录（code=E_SKIP_ALREADY_ONLINE，失败分类=配置缺失）`。
     *
     * **新增在 `CONFIG_MISSING` 之后（既有取值的名称与相对顺序零改动）**：既有取值可能被离线核对
     * 断言引用；新增值紧随语义相邻的位置，不追加到末尾是为了让「已在线」与「配置缺失」这对
     * 真机上互相误报的取值相邻可读。
     *
     * **只覆盖 `E_SKIP_ALREADY_ONLINE`**：其它 `E_SKIP_*`（`E_SKIP_NO_SSID` / `E_SKIP_UNBOUND` /
     * `E_SKIP_SSID_MISMATCH` / `E_SKIP_NOT_SRUN` / `E_SKIP_PROBE_UNCERTAIN`）语义仍是
     * 「本次跳过、需等条件变化」，**行为保持不变**（负例见 `artifacts/onlinefix1/jvm-classify-test.txt`）。
     */
    ALREADY_ONLINE("已在线，无需登录"),
    PARSE_FAILED("响应解析失败"),
    PROTOCOL_ERROR("协议异常"),
    UNKNOWN("未知错误")
}

/** 认证阶段常量（写入 [AuthResult.stage]）。 */
object AuthStage {
    const val CONFIG = "config"
    const val CHALLENGE = "challenge"
    const val LOGIN = "login"
    const val VERIFY = "verify"
}

/** 认证客户端错误码（与参考实现 srun-login.js 的 E_* 口径一致）。 */
object AuthCodes {
    const val OK = "ok"
    const val E_CONFIG = "E_CONFIG"
    const val E_NETWORK = "E_NETWORK"
    const val E_PORTAL = "E_PORTAL"
    const val E_CHALLENGE = "E_CHALLENGE"
    const val E_PARSE = "E_PARSE"
    const val E_REJECTED = "E_REJECTED"
    const val E_UNKNOWN = "E_UNKNOWN"
}

/** 网络层返回的响应包（业务无关）。 */
data class AuthResponse(val status: Int, val body: String)

/**
 * 网络层注入点：认证客户端只通过它发请求，使上层可在 JVM 上用手写假实现测试。
 */
interface AuthTransport {
    /** 执行一次认证（两步 GET + JSONP）。实现不得抛出异常，一切失败都要落成 [AuthResult]。 */
    fun execute(req: AuthRequest): AuthResult
}

/** 错误分类函数（纯逻辑，可离线测试）。 */
object AuthFailureClassifier {

    /**
     * 由错误码与阶段推导错误分类。
     *
     * - E_NETWORK / E_PORTAL → 网络不可达 / Portal 不可达
     * - E_CONFIG            → 配置缺失
     * - E_PARSE             → 响应解析失败
     * - E_CHALLENGE / 服务端业务码（数字 ecode）→ 协议异常 / 业务拒绝
     * - 【onlinefix1 任务 A 段】E_SKIP_ALREADY_ONLINE → [AuthFailure.ALREADY_ONLINE]（**目标已达成**）
     *
     * **为什么必须显式列出 `E_SKIP_ALREADY_ONLINE`**：它不带 `stage`（跳过的 stage 是 `"skip"`），
     * 落到 `else` 里既不是 LOGIN/VERIFY 也不是已知错误码 → 返回 [AuthFailure.UNKNOWN]；
     * 真机上它被 UI 的 `failure?.displayName` 显示成「配置缺失」（经 `flow.AuthSkip.toResult`
     * 的兜底分类），用户看到的就是「失败（配置缺失）」——与真实情况（已在线）完全相反。
     *
     * **只加这一条**：其它 `E_SKIP_*` 一律走原路径（行为不变）。
     */
    fun classify(code: String, stage: String): AuthFailure = when (code) {
        AuthCodes.E_NETWORK -> AuthFailure.NETWORK_UNREACHABLE
        AuthCodes.E_PORTAL -> AuthFailure.PORTAL_UNREACHABLE
        AuthCodes.E_CONFIG -> AuthFailure.CONFIG_MISSING
        AuthCodes.E_PARSE -> AuthFailure.PARSE_FAILED
        AuthCodes.E_CHALLENGE -> AuthFailure.PROTOCOL_ERROR
        AuthResultStatus.CODE_ALREADY_ONLINE -> AuthFailure.ALREADY_ONLINE
        else -> if (stage == AuthStage.LOGIN || stage == AuthStage.VERIFY) {
            AuthFailure.REJECTED
        } else {
            AuthFailure.UNKNOWN
        }
    }
}
