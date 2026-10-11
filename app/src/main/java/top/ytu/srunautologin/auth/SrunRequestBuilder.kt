package top.ytu.srunautologin.auth

import top.ytu.srunautologin.crypto.SrunCrypto

/**
 * 请求参数组装（纯逻辑，零第三方依赖，可离线逐字段核对）。
 *
 * B10 端到端复用（唯一密码学来源 = 已冻结的 top.ytu.srunautologin.crypto.SrunCrypto）：
 *  - 调用点 1：本文件 [portalParams] → `SrunCrypto.hmacMd5(token, plainPwd)`（hmd5 中间量，供 chksum 使用）
 *  - 调用点 2：本文件 [portalParams] → `SrunCrypto.passwordField(plainPwd, token)`
 *  - 调用点 3：本文件 [portalParams] → `SrunCrypto.infoField(username, plainPwd, ip, acId, token)`
 *  - 调用点 4：本文件 [portalParams] → `SrunCrypto.chksum(token, username, hmd5, acId, ip, n, type, info)`
 * 本文件**不实现任何哈希/编码/加密算法**，只做参数拼装与 URL 编码（java.net.URLEncoder）。
 */
object SrunRequestBuilder {

    /** 门户地址归一化：去空白、去尾部 '/'，无协议时补 "http://"。 */
    fun normalizePortal(portal: String): String {
        var p = portal.trim()
        while (p.endsWith("/")) p = p.dropLast(1)
        if (p.isEmpty()) return ""
        if (!p.startsWith("http://") && !p.startsWith("https://")) p = "http://$p"
        return p
    }

    /**
     * 第一步 URL：`GET {portal}/cgi-bin/get_challenge?username=<user>&ip=<ip>&callback=callback`
     * （参数顺序对齐 srun-login.js:306-314）。
     */
    fun challengeUrl(req: AuthRequest, ip: String): String =
        buildUrl(
            normalizePortal(req.portal) + SrunProtocol.PATH_CHALLENGE,
            listOf(
                "username" to req.username,
                "ip" to ip,
                SrunProtocol.CALLBACK_PARAM to SrunProtocol.CALLBACK_NAME
            )
        )

    /**
     * 第二步参数表（**顺序固定**，逐字对齐参考实现 artifacts/srun-impl/srun-login.js:361-380）。
     *
     * password / info / chksum 全部由已冻结的 SrunCrypto 生成（见文件头调用点清单）。
     */
    fun portalParams(
        req: AuthRequest,
        token: String,
        ip: String,
        mockFail: Boolean = false,
        nowMillis: Long = 0L
    ): List<Pair<String, String>> {
        // 调用点 1：hmd5 中间量（参考实现 cryptoMod.hmacMd5(ch.token, cfg.password)）
        val hmd5 = SrunCrypto.hmacMd5(token, req.password)
        // 调用点 2：password 字段
        val password = SrunCrypto.passwordField(req.password, token)
        // 调用点 3：info 字段（{SRBX1} + 自定义 base64(xEncode(JSON)))
        val info = SrunCrypto.infoField(req.username, req.password, ip, req.acId, token)
        // 调用点 4：chksum（SHA1，token 作首字段与分隔符）
        val chksum = SrunCrypto.chksum(
            token = token,
            username = req.username,
            hmd5 = hmd5,
            acId = req.acId,
            ip = ip,
            n = SrunProtocol.N,
            type = SrunProtocol.TYPE,
            info = info
        )
        val params = mutableListOf(
            SrunProtocol.CALLBACK_PARAM to SrunProtocol.CALLBACK_NAME,
            "action" to "login",
            "username" to req.username,
            "password" to password,
            "ac_id" to req.acId,
            "ip" to ip,
            "chksum" to chksum,
            "info" to info,
            "n" to SrunProtocol.N.toString(),
            "type" to SrunProtocol.TYPE.toString(),
            "os" to SrunProtocol.OS,
            "name" to SrunProtocol.OS,
            "double_stack" to SrunProtocol.DOUBLE_STACK.toString()
        )
        // 仅本机 mock 自测用（真实环境不设置）；同参考实现 cfg.mockFail。
        if (mockFail) params.add("fail" to "1")
        if (nowMillis > 0L) params.add("_" to nowMillis.toString())
        return params
    }

    /** 第二步 URL。 */
    fun portalUrl(
        req: AuthRequest,
        token: String,
        ip: String,
        mockFail: Boolean = false,
        nowMillis: Long = 0L
    ): String = buildUrl(
        normalizePortal(req.portal) + SrunProtocol.PATH_PORTAL,
        portalParams(req, token, ip, mockFail, nowMillis)
    )

    /** 按参数表顺序拼 URL；用 java.net.URLEncoder 做表单编码（空格 → '+'，与 URLSearchParams 一致）。 */
    fun buildUrl(base: String, params: List<Pair<String, String>>): String {
        val sb = StringBuilder(base)
        var first = true
        for ((k, v) in params) {
            sb.append(if (first) '?' else '&')
            first = false
            sb.append(encode(k)).append('=').append(encode(v))
        }
        return sb.toString()
    }

    fun encode(s: String): String = java.net.URLEncoder.encode(s, "UTF-8")
}
