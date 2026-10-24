package top.ytu.srunautologin.auth

import top.ytu.srunautologin.crypto.SrunCrypto

object SrunRequestBuilder {

    /** Preserve the configured transport, host and port; bare hosts default to HTTPS. */
    fun normalizePortal(portal: String): String = PortalEndpoint.normalize(portal).orEmpty()

    fun challengeUrl(req: AuthRequest, ip: String): String =
        buildUrl(
            normalizePortal(req.portal) + SrunProtocol.PATH_CHALLENGE,
            listOf(
                "username" to req.username,
                "ip" to ip,
                SrunProtocol.CALLBACK_PARAM to SrunProtocol.CALLBACK_NAME
            )
        )

    fun portalParams(
        req: AuthRequest,
        token: String,
        ip: String,
        mockFail: Boolean = false,
        nowMillis: Long = 0L
    ): List<Pair<String, String>> {
        val hmd5 = SrunCrypto.hmacMd5(token, req.password)
        val password = SrunCrypto.passwordField(req.password, token)
        val info = SrunCrypto.infoField(req.username, req.password, ip, req.acId, token)
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
        if (mockFail) params.add("fail" to "1")
        if (nowMillis > 0L) params.add("_" to nowMillis.toString())
        return params
    }

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
