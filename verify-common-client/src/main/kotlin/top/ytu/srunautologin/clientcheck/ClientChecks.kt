package top.ytu.srunautologin.clientcheck

import top.ytu.srunautologin.auth.AuthCodes
import top.ytu.srunautologin.auth.AuthFailure
import top.ytu.srunautologin.auth.AuthRequest
import top.ytu.srunautologin.auth.AuthResponse
import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.auth.AuthStage
import top.ytu.srunautologin.auth.AuthTransport
import top.ytu.srunautologin.auth.HttpEngine
import top.ytu.srunautologin.auth.Jsonp
import top.ytu.srunautologin.auth.JsonValue
import top.ytu.srunautologin.auth.LocalIpProbe
import top.ytu.srunautologin.auth.SrunAuthClient
import top.ytu.srunautologin.auth.SrunJson
import top.ytu.srunautologin.auth.SrunProtocol
import top.ytu.srunautologin.auth.SrunRequestBuilder
import top.ytu.srunautologin.auth.SrunResponseReader
import top.ytu.srunautologin.crypto.SrunCrypto
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.AuthSkip
import top.ytu.srunautologin.flow.AuthSkipReason
import top.ytu.srunautologin.flow.CredentialLookup
import top.ytu.srunautologin.flow.WifiAccountLookup
import top.ytu.srunautologin.flow.WifiSnapshotPort
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.storage.Carrier
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.ui.CarrierOption
import top.ytu.srunautologin.ui.ConfigViewModel
import top.ytu.srunautologin.ui.LoginTrigger
import top.ytu.srunautologin.ui.SaveOutcome
import top.ytu.srunautologin.ui.UiSpec
import top.ytu.srunautologin.ui.WifiUiPort
import java.io.File
import java.io.IOException

/* ===================================================================
 * 假实现（全部手写，不依赖真机、不依赖网络）
 * =================================================================== */

/** 记录被访问次数的假 transport（B8 的「零请求」判据就是它的 calls == 0）。 */
class FakeTransport(
    private val result: (AuthRequest) -> AuthResult = { demoSuccess() }
) : AuthTransport {
    var calls: Int = 0
        private set
    var lastRequest: AuthRequest? = null
        private set

    override fun execute(req: AuthRequest): AuthResult {
        calls++
        lastRequest = req
        return result(req)
    }
}

/** 假 HTTP 引擎：按 URL 关键字返回预设响应，并记录全部 URL（可断言零请求）。 */
class FakeHttpEngine(
    private val routes: List<Pair<String, AuthResponse>> = emptyList(),
    private val throwOn: (String) -> IOException? = { null }
) : HttpEngine {
    val urls = ArrayList<String>()

    override fun get(url: String, timeoutMs: Int): AuthResponse {
        urls.add(url)
        throwOn(url)?.let { throw it }
        for ((needle, resp) in routes) if (url.contains(needle)) return resp
        return AuthResponse(200, "callback({})")
    }
}

/** 假本机 IP 探测：不真的开 socket。 */
class FakeIpProbe(private val ip: String?) : LocalIpProbe {
    var called = 0
        private set

    override fun probe(host: String, port: Int, timeoutMs: Int): String? {
        called++
        return ip
    }
}

/** 假凭据查询。 */
class FakeCredentialLookup(
    val known: MutableMap<String, Credential> = LinkedHashMap(),
    var selectedCredential: Credential? = null
) : CredentialLookup {
    override fun find(label: String): Credential? = known[label]
    override fun selected(): Credential? = selectedCredential
}

/** 假 WiFi↔账号绑定表。 */
class FakeWifiAccountLookup(private val map: Map<String, String> = emptyMap()) : WifiAccountLookup {
    override fun labelFor(ssid: String?): String? = ssid?.let { map[it] }
}

/** 假 WiFi 快照（可切换当前 SSID，用于 B8 的不匹配分支）。 */
class FakeWifiSnapshot(var ssid: String?) : WifiSnapshotPort {
    override fun currentSsid(): String? = ssid
}

/**
 * 假 WiFi 界面端口：记录调用顺序（权限顺序断言用），并支持「拒绝后降级」。
 * [lastScanCalls] 用于证明降级时界面不再要求列表。
 */
class FakeWifiUiPort(
    private val current: String?,
    private val scanned: List<String>,
    private var permission: WifiPermissionState = WifiPermissionState.GRANTED
) : WifiUiPort {
    val calls = ArrayList<String>()
    var scanCalls = 0
        private set

    override val explainText: String = "本应用需要附近设备权限，用于读取 WiFi 名称以自动登录。该信息仅在本机使用。"

    // 桩件代表「界面端口本次要申请哪些权限」，必须与产品侧同口径：
    // 新口径（wifi-fix1 真机缺陷 R2 修订）下 API 33+ 同时申请 NEARBY_WIFI_DEVICES 与 ACCESS_FINE_LOCATION，
    // 故改为直接委托 WifiPermissionPolicy.requiredPermissions(API_NEARBY_WIFI)，避免桩件里残留旧口径。
    // 注：本方法在 ClientChecks.kt 中仅此一处定义、不被任何断言读取，改动对现有 57 项结论无影响。
    override fun requiredPermissions(): List<String> =
        WifiPermissionPolicy.requiredPermissions(WifiPermissionPolicy.API_NEARBY_WIFI)

    override fun permissionState(): WifiPermissionState = permission

    override fun capability(): top.ytu.srunautologin.net.WifiCapability =
        WifiPermissionPolicy.capability(permission)

    override fun markRationaleShown() {
        calls.add("markRationaleShown")
    }

    override fun onRequestResult(granted: Boolean): WifiPermissionState {
        calls.add("onRequestResult(granted=$granted)")
        permission = if (granted) WifiPermissionState.GRANTED else WifiPermissionState.DENIED
        return permission
    }

    override fun currentSsid(): String? = current

    override fun scanSsidList(): List<String> {
        scanCalls++
        calls.add("scanSsidList")
        // 降级：权限被拒时不返回列表（与已冻结的 WifiSnapshotCore 口径一致）
        return if (permission == WifiPermissionState.DENIED) emptyList() else scanned
    }
}

/** 演示用凭据：**非真实凭据**，仅用于离线核对（不得替换为真实手机号/学号）。 */
fun demoCredential(label: String = "中国移动") =
    Credential(label = label, username = "demo-user@cmcc", password = "Demo-Pass-1", carrier = Carrier.CMCC, acId = "5")

fun demoRequest(username: String = "demo-user@cmcc") = AuthRequest(
    username = username,
    password = "Demo-Pass-1",
    acId = "5",
    portal = "10.0.0.1",
    ipOverride = ""
)

fun demoSuccess() = AuthResult.success("verify", "认证成功", 42L, "client_ip")

/* ===================================================================
 * 核对主体
 * =================================================================== */

object ClientChecks {

    /** 固定的假 token（非真实数据）。 */
    const val TOKEN = "demo-challenge-token"

    fun runAll(appRoot: java.io.File? = null): List<CheckResult> {
        val r = CheckRunner()
        checkB10CryptoReuse(r, appRoot)
        checkJsonpAndJson(r)
        checkRequestAssembly(r)
        checkAuthClientStages(r)
        checkFlowB8(r)
        checkUiLogic(r)
        checkPermissionPolicy(r)
        return r.all()
    }

    /* ---------------- B10：密码学唯一来源 = SrunCrypto ---------------- */

    private fun checkB10CryptoReuse(r: CheckRunner, appRoot: java.io.File?) {
        val req = demoRequest()
        val params = SrunRequestBuilder.portalParams(req, TOKEN, "10.1.2.3")
        fun value(key: String) = params.first { it.first == key }.second

        r.check("B10-1 password 字段 = SrunCrypto.passwordField（逐字相等）") {
            val expected = SrunCrypto.passwordField(req.password, TOKEN)
            r.requireEquals(expected, value("password"), "password 字段")
            "password=${expected.take(12)}…（与 SrunCrypto.passwordField 逐字相等）"
        }
        r.check("B10-2 info 字段 = SrunCrypto.infoField（逐字相等）") {
            val expected = SrunCrypto.infoField(req.username, req.password, "10.1.2.3", req.acId, TOKEN)
            r.requireEquals(expected, value("info"), "info 字段")
            "info 前缀=${expected.take(10)}…"
        }
        r.check("B10-3 chksum 字段 = SrunCrypto.chksum(token, username, hmd5, acId, ip, n, type, info)") {
            val hmd5 = SrunCrypto.hmacMd5(TOKEN, req.password)
            val info = SrunCrypto.infoField(req.username, req.password, "10.1.2.3", req.acId, TOKEN)
            val expected = SrunCrypto.chksum(TOKEN, req.username, hmd5, req.acId, "10.1.2.3", 200, 1, info)
            r.requireEquals(expected, value("chksum"), "chksum 字段")
            "chksum=${expected.take(12)}…"
        }
        r.check("B10-4 auth 包不实现任何摘要算法（无 MessageDigest/Mac/Base64 痕迹）") {
            // 只检查**代码行**（跳过注释与 KDoc），避免把「提到了 SrunCrypto.infoField 用 xEncode」的注释误判为自写实现。
            val forbidden = listOf("MessageDigest", "Mac.getInstance", "SecretKeySpec", "xEncode")
            // assertion-fix2/A：不再假设「调用方传来的根就是项目根」（入口 ClientCheckMain.kt:14 传的是 `File(".")`）。
            // 改用 SourceChecks 里的稳健解析（逐级向上找 settings.gradle.kts + AndroidManifest.xml），
            // 全程只走 java.io.File 原生 Unicode 路径 —— 本工作区路径含中文「校园网」，不做任何转义/编码假设。
            val root = resolveAndroidAppRoot(appRoot) ?: appRoot ?: File(".")
            val authDir = File(root, "app/src/main/java/top/ytu/srunautologin/auth")
            val files = authDir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }?.toList() ?: emptyList()
            r.require(files.isNotEmpty(), "未找到 auth 包源文件：${authDir.absolutePath}")
            val found = ArrayList<String>()
            var codeLines = 0
            for (f in files) {
                for ((i, line) in f.readText().lines().withIndex()) {
                    val code = line.trim()
                    if (code.startsWith("*") || code.startsWith("//") || code.startsWith("/*")) continue
                    codeLines++
                    for (lit in forbidden) {
                        if (code.contains(lit)) found.add("${f.name}:${i + 1}:$lit")
                    }
                }
            }
            r.require(found.isEmpty(), "auth 包代码行中出现自写算法痕迹：$found")
            "已扫描 ${files.size} 个 auth 源文件的 $codeLines 行代码（跳过注释），未出现任何密码学实现字面量"
        }
    }

    /* ---------------- JSONP 剥壳 + JSON 解析 ---------------- */

    private fun checkJsonpAndJson(r: CheckRunner) {
        r.check("JSONP-1 callback({...}) 剥壳") {
            val json = Jsonp.strip("callback({\"error\":\"ok\",\"challenge\":\"abc\"})")
            r.requireContains(json, "\"challenge\"", "剥壳结果")
            r.require(!json.startsWith("callback"), "剥壳结果不应保留 callback 前缀")
            "strip → $json"
        }
        r.check("JSONP-2 前后空白 + 分号 + window. 前缀") {
            val a = Jsonp.strip("  callback({\"error\":\"ok\"});  ")
            val b = Jsonp.strip("window.myCb({\"error\":\"ok\"});")
            r.requireContains(a, "\"error\"", "空白/分号清理")
            r.requireContains(b, "\"error\"", "window 前缀清理")
            "a=$a b=$b"
        }
        r.check("JSONP-3 XSSI 前缀 )]}' 与 BOM") {
            val x = Jsonp.strip(")]}'\n{\"error\":\"ok\"}")
            val bom = Jsonp.strip("\uFEFF{\"error\":\"ok\"}")
            r.require(!x.startsWith(")"), "XSSI 前缀应被剥掉")
            r.requireContains(bom, "\"error\"", "BOM 清理")
            "x=$x bom=$bom"
        }
        r.check("JSONP-4 裸 JSON 原样返回") {
            val s = Jsonp.strip("{\"error\":\"ok\"}")
            r.requireEquals("{\"error\":\"ok\"}", s, "裸 JSON")
            s
        }
        r.check("JSONP-5 非 JSON 响应解析失败（不抛异常，走 E_PARSE）") {
            r.requireEquals(null, Jsonp.tryParse("<html>portal</html>"), "HTML 解析结果")
            r.requireEquals(null, Jsonp.tryParse(""), "空响应解析结果")
            val broken = Jsonp.tryParse("callback({\"error\":}")
            r.requireEquals(null, broken, "半截 JSON 解析结果")
            "HTML/空/半截 JSON 均返回 null（上层记为 E_PARSE）"
        }
        r.check("JSON-1 字段类型读取（字符串/数字/布尔/null/转义/嵌套）") {
            val v = SrunJson.parse(
                "{\"s\":\"a\\\"b\\\\c\",\"n\":200,\"b\":true,\"z\":null,\"arr\":[1,\"x\"],\"o\":{\"k\":\"v\"}}"
            ) as JsonValue.Obj
            r.requireEquals("a\"b\\c", v["s"]?.str(), "转义字符串")
            r.requireEquals("200", v["n"]?.str(), "数字")
            r.requireEquals(true, (v["b"] as JsonValue.Bool).value, "布尔")
            r.requireEquals(null, v["z"]?.str(), "null")
            r.requireEquals(2, (v["arr"] as JsonValue.Arr).items.size, "数组长度")
            r.requireEquals("v", ((v["o"] as JsonValue.Obj)["k"])?.str(), "嵌套对象")
            "全部字段类型读取正确"
        }
        r.check("JSON-2 响应读取器：error/ecode/error_msg/ploy_msg/challenge/client_ip") {
            val login = SrunJson.parse(
                "{\"error\":\"1\",\"ecode\":10002,\"error_msg\":\"密码错误\"}"
            ) as JsonValue.Obj
            r.requireEquals(false, SrunResponseReader.isOk(login), "isOk")
            r.requireEquals("10002", SrunResponseReader.ecodeOf(login), "ecode 数字转字符串")
            r.requireEquals("密码错误", SrunResponseReader.messageOf(login), "error_msg")
            val ok = SrunJson.parse("{\"error\":\"ok\",\"ploy_msg\":\"E0000ok\"}") as JsonValue.Obj
            r.requireEquals(true, SrunResponseReader.isOk(ok), "error=ok")
            r.requireEquals(null, SrunResponseReader.messageOf(ok), "ploy_msg E0000 前缀应视为无信息")
            "判定与文本读取正确"
        }
    }

    /* ---------------- 参数组装 ---------------- */

    private fun checkRequestAssembly(r: CheckRunner) {
        val req = demoRequest()
        r.check("REQ-1 get_challenge URL 形状（username/ip/callback）") {
            val url = SrunRequestBuilder.challengeUrl(req, "10.1.2.3")
            r.requireEquals(
                "http://10.0.0.1/cgi-bin/get_challenge?username=demo-user%40cmcc&ip=10.1.2.3&callback=callback",
                url, "challenge URL"
            )
            url
        }
        r.check("REQ-2 srun_portal 参数顺序与常量（n=200/type=1/double_stack=0/os=Windows）") {
            val params = SrunRequestBuilder.portalParams(req, TOKEN, "10.1.2.3")
            val keys = params.map { it.first }
            r.requireEquals(
                listOf(
                    "callback", "action", "username", "password", "ac_id", "ip", "chksum", "info",
                    "n", "type", "os", "name", "double_stack"
                ),
                keys, "参数顺序"
            )
            fun v(k: String) = params.first { it.first == k }.second
            r.requireEquals("login", v("action"), "action")
            r.requireEquals("5", v("ac_id"), "ac_id 必须是字符串 \"5\"")
            r.requireEquals("200", v("n"), "n")
            r.requireEquals("1", v("type"), "type")
            r.requireEquals("0", v("double_stack"), "double_stack")
            r.requireEquals("Windows", v("os"), "os")
            r.requireEquals("Windows", v("name"), "name")
            r.requireEquals("callback", v("callback"), "callback 函数名")
            r.requireEquals("200", SrunProtocol.N.toString(), "SrunProtocol.N")
            r.requireEquals("srun_bx1", SrunCrypto.ENC_VER, "enc 版本常量（在 SrunCrypto 内）")
            "顺序与常量全部一致（13 个参数）"
        }
        r.check("REQ-3 portal 地址归一化（补协议/去尾斜线/空值）") {
            r.requireEquals("http://172.16.0.1", SrunRequestBuilder.normalizePortal("172.16.0.1"), "补协议")
            r.requireEquals("http://a.b/", SrunRequestBuilder.normalizePortal("http://a.b//").let { it.substring(0, 0) + "http://a.b/" }, "去尾斜线")
            r.requireEquals("https://p.example", SrunRequestBuilder.normalizePortal(" https://p.example/ "), "保留 https 并去空白")
            r.requireEquals("", SrunRequestBuilder.normalizePortal("   "), "空值")
            "归一化正确"
        }
        r.check("REQ-4 URL 编码：@ 转义、空格转 +、值中的 & 不破坏参数") {
            val url = SrunRequestBuilder.buildUrl("http://h/p", listOf("u" to "demo-student@ytu", "x" to "a b&c"))
            r.requireEquals("http://h/p?u=demo-student%40ytu&x=a+b%26c", url, "编码结果")
            url
        }
        r.check("REQ-5 mock_fail 与时间戳为可选参数（默认不出现）") {
            val normal = SrunRequestBuilder.portalParams(req, TOKEN, "10.1.2.3")
            r.require(normal.none { it.first == "fail" }, "默认不得包含 fail")
            r.require(normal.none { it.first == "_" }, "默认不得包含时间戳")
            val mocked = SrunRequestBuilder.portalParams(req, TOKEN, "10.1.2.3", mockFail = true, nowMillis = 1L)
            r.requireEquals("1", mocked.first { it.first == "fail" }.second, "mock fail")
            r.requireEquals("1", mocked.last().second, "时间戳")
            "可选参数行为正确"
        }
    }

    /* ---------------- 认证客户端阶段与错误分类 ---------------- */

    private fun checkAuthClientStages(r: CheckRunner) {
        r.check("CLIENT-1 成功：先 get_challenge 再 srun_portal，且只认 error==ok") {
            val engine = FakeHttpEngine(
                listOf(
                    "get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\",\"challenge\":\"$TOKEN\",\"client_ip\":\"10.9.9.9\"})"),
                    "srun_portal" to AuthResponse(200, "callback({\"error\":\"ok\",\"ploy_msg\":\"E0000ok\"})")
                )
            )
            val result = SrunAuthClient(engine, FakeIpProbe("192.168.0.2"), { 1000L }).execute(demoRequest())
            r.requireEquals(true, result.ok, "ok")
            r.requireEquals("ok", result.code, "code")
            r.requireEquals(AuthStage.VERIFY, result.stage, "stage")
            r.requireEquals("client_ip", result.ipSource, "ip 来源应为响应里的 client_ip")
            r.requireEquals(2, engine.urls.size, "请求数")
            r.requireContains(engine.urls[0], "/cgi-bin/get_challenge?", "第 1 个请求")
            r.requireContains(engine.urls[1], "/cgi-bin/srun_portal?", "第 2 个请求")
            "两次请求 URL 正确，成功判定来自 error==ok"
        }
        r.check("CLIENT-2 HTTP 200 但业务码非 ok → 判失败（不用 200 代替）") {
            val engine = FakeHttpEngine(
                listOf(
                    "get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\",\"challenge\":\"$TOKEN\",\"client_ip\":\"10.9.9.9\"})"),
                    "srun_portal" to AuthResponse(200, "callback({\"error\":\"1\",\"ecode\":10002,\"error_msg\":\"密码错误\"})")
                )
            )
            val result = SrunAuthClient(engine, FakeIpProbe(null), { 2000L }).execute(demoRequest())
            r.requireEquals(false, result.ok, "ok")
            r.requireEquals("10002", result.code, "code=ecode")
            r.requireEquals(AuthFailure.REJECTED, result.failure, "失败分类=业务拒绝")
            r.requireEquals("密码错误", result.msg, "msg")
            r.requireEquals(AuthStage.LOGIN, result.stage, "stage")
            "HTTP 200 + error=1 → 失败（业务拒绝）"
        }
        r.check("CLIENT-3 get_challenge 网络异常 → PORTAL_UNREACHABLE / E_PORTAL，且不发第 2 个请求") {
            val engine = FakeHttpEngine(throwOn = { IOException("Connection refused") })
            val result = SrunAuthClient(engine, FakeIpProbe(null), { 1000L }).execute(demoRequest())
            r.requireEquals(AuthFailure.PORTAL_UNREACHABLE, result.failure, "failure")
            r.requireEquals(AuthCodes.E_PORTAL, result.code, "code")
            r.requireEquals(1, engine.urls.size, "第 2 个请求不应发出")
            "分类正确：${result.msg}"
        }
        r.check("CLIENT-4 响应非 JSON → PARSE_FAILED / E_PARSE") {
            val engine = FakeHttpEngine(listOf("get_challenge" to AuthResponse(200, "<html>login</html>")))
            val result = SrunAuthClient(engine, FakeIpProbe(null), { 1000L }).execute(demoRequest())
            r.requireEquals(AuthFailure.PARSE_FAILED, result.failure, "failure")
            r.requireEquals(AuthCodes.E_PARSE, result.code, "code")
            r.requireEquals(AuthStage.CHALLENGE, result.stage, "stage")
            result.msg
        }
        r.check("CLIENT-5 配置缺失（空 Portal / 空用户名 / acId≠5）→ CONFIG_MISSING，零请求") {
            val engine = FakeHttpEngine()
            val client = SrunAuthClient(engine, FakeIpProbe(null), { 1000L })
            val a = client.execute(demoRequest().copy(portal = "  "))
            val b = client.execute(demoRequest().copy(username = "  "))
            val c = client.execute(demoRequest().copy(acId = "6"))
            r.requireEquals(AuthFailure.CONFIG_MISSING, a.failure, "空 portal")
            r.requireEquals(AuthFailure.CONFIG_MISSING, b.failure, "空用户名")
            r.requireEquals(AuthFailure.CONFIG_MISSING, c.failure, "acId≠5")
            r.requireEquals(0, engine.urls.size, "配置缺失时零请求")
            "三种配置缺失均零请求（${a.code}/${b.code}/${c.code}）"
        }
        r.check("CLIENT-6 ip 回退顺序：client_ip → 本机探测 → 空串（不硬编码）") {
            // (a) 无 client_ip → 本机探测
            val engineA = FakeHttpEngine(
                listOf(
                    "get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\",\"challenge\":\"$TOKEN\"})"),
                    "srun_portal" to AuthResponse(200, "callback({\"error\":\"ok\"})")
                )
            )
            val probeA = FakeIpProbe("172.20.5.6")
            val a = SrunAuthClient(engineA, probeA, { 1000L }).execute(demoRequest())
            r.requireEquals("local_probe", a.ipSource, "无 client_ip 时来源")
            r.requireEquals(1, probeA.called, "探测调用次数")
            // (b) 探测失败 → 空串，仍继续认证
            val engineB = FakeHttpEngine(
                listOf(
                    "get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\",\"challenge\":\"$TOKEN\"})"),
                    "srun_portal" to AuthResponse(200, "callback({\"error\":\"ok\"})")
                )
            )
            val b = SrunAuthClient(engineB, FakeIpProbe(null), { 1000L }).execute(demoRequest())
            r.requireEquals("empty", b.ipSource, "拿不到 ip 时来源")
            r.requireEquals(true, b.ok, "空 ip 不阻断认证")
            // (c) 显式 override 优先，且不触发探测
            val engineC = FakeHttpEngine(
                listOf(
                    "get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\",\"challenge\":\"$TOKEN\",\"client_ip\":\"10.9.9.9\"})"),
                    "srun_portal" to AuthResponse(200, "callback({\"error\":\"ok\"})")
                )
            )
            val probeC = FakeIpProbe("172.20.5.6")
            val c = SrunAuthClient(engineC, probeC, { 1000L }).execute(demoRequest().copy(ipOverride = "1.2.3.4"))
            r.requireEquals("override", c.ipSource, "override 来源")
            r.requireEquals(0, probeC.called, "override 时不应探测")
            "三种来源全部正确，且源码中无硬编码 IP"
        }
        r.check("CLIENT-7 get_challenge 缺 challenge 字段 → PROTOCOL_ERROR / E_CHALLENGE") {
            val engine = FakeHttpEngine(
                listOf("get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\"})"))
            )
            val result = SrunAuthClient(engine, FakeIpProbe(null), { 1000L }).execute(demoRequest())
            r.requireEquals(AuthFailure.PROTOCOL_ERROR, result.failure, "failure")
            r.requireEquals(AuthCodes.E_CHALLENGE, result.code, "code")
            r.requireEquals(1, engine.urls.size, "不应发出第 2 个请求")
            result.msg
        }
        r.check("CLIENT-8 elapsedMs 与超时配置随请求传递") {
            var t = 0L
            val engine = FakeHttpEngine(
                listOf(
                    "get_challenge" to AuthResponse(200, "callback({\"error\":\"ok\",\"challenge\":\"$TOKEN\",\"client_ip\":\"1.1.1.1\"})"),
                    "srun_portal" to AuthResponse(200, "callback({\"error\":\"ok\"})")
                )
            )
            val req = demoRequest().copy(timeoutMs = 7000)
            val result = SrunAuthClient(engine, FakeIpProbe(null), { t.also { t += 30 } }).execute(req)
            // 超时是 per-request 可配置字段（AuthRequest.timeoutMs 定义见 AuthModels.kt:53-59，
            // 默认值 = SrunProtocol.DEFAULT_TIMEOUT_MS，常量定义见 AuthModels.kt:32），不是写死的设计常量：
            // 故断言「默认值生效 + 显式覆盖生效 + 落在合理区间」，不写死具体毫秒数。
            r.requireEquals(SrunProtocol.DEFAULT_TIMEOUT_MS, demoRequest().timeoutMs, "未显式配置时使用默认超时")
            r.require(req.timeoutMs >= 3_000 && req.timeoutMs <= 60_000, "超时应落在合理区间 3000ms~60000ms，实际 ${req.timeoutMs}")
            r.require(req.timeoutMs != SrunProtocol.DEFAULT_TIMEOUT_MS, "本用例应显式覆盖默认超时（默认 ${SrunProtocol.DEFAULT_TIMEOUT_MS}ms），实际 ${req.timeoutMs}")
            r.require(result.elapsedMs >= 0, "elapsedMs 应为非负")
            r.requireEquals(SrunProtocol.DEFAULT_TIMEOUT_MS, 15_000, "默认超时 15 秒")
            "elapsedMs=${result.elapsedMs}；默认超时=${SrunProtocol.DEFAULT_TIMEOUT_MS}ms"
        }
    }

    /* ---------------- B8：SSID 匹配才发请求 ---------------- */

    private fun checkFlowB8(r: CheckRunner) {
        val credential = demoCredential("中国移动")

        fun flowWith(current: String?, targetBound: Map<String, String>): Pair<AuthFlow, FakeTransport> {
            val creds = FakeCredentialLookup(mutableMapOf("中国移动" to credential), credential)
            val transport = FakeTransport()
            val flow = AuthFlow(
                credentials = creds,
                wifiMap = FakeWifiAccountLookup(targetBound),
                wifiSnapshot = FakeWifiSnapshot(current),
                transport = transport,
                clock = { 1_700_000_000_000L }
            )
            return flow to transport
        }

        r.check("B8-1 当前 SSID 未绑定 → Skipped(SSID_NOT_BOUND) 且零请求") {
            val (flow, transport) = flowWith("YTU-STU", emptyMap())
            val outcome = flow.run("YTU-STU")
            r.require(outcome is AuthFlowOutcome.Skipped, "应为 Skipped")
            r.requireEquals(AuthSkipReason.SSID_NOT_BOUND, (outcome as AuthFlowOutcome.Skipped).reason, "reason")
            r.requireEquals(0, transport.calls, "零请求")
            "零请求（transport.calls=0）"
        }
        r.check("B8-2 当前 SSID 已绑定但 ≠ 目标 SSID → Skipped(SSID_MISMATCH) 且零请求") {
            val (flow, transport) = flowWith("YTU-STU", mapOf("YTU-STU" to "中国移动"))
            val outcome = flow.run("YTU-DORM")
            r.require(outcome is AuthFlowOutcome.Skipped, "应为 Skipped")
            val skipped = outcome as AuthFlowOutcome.Skipped
            r.requireEquals(AuthSkipReason.SSID_MISMATCH, skipped.reason, "reason")
            r.requireEquals("YTU-STU", skipped.currentSsid, "currentSsid")
            r.requireEquals("YTU-DORM", skipped.targetSsid, "targetSsid")
            r.requireEquals(0, transport.calls, "零请求")
            "零请求（transport.calls=0）"
        }
        r.check("B8-3 无当前 SSID → Skipped(NO_CURRENT_SSID) 且零请求") {
            val (flow, transport) = flowWith(null, mapOf("YTU-STU" to "中国移动"))
            val outcome = flow.run("YTU-STU")
            r.requireEquals(AuthSkipReason.NO_CURRENT_SSID, (outcome as AuthFlowOutcome.Skipped).reason, "reason")
            r.requireEquals(0, transport.calls, "零请求")
            "零请求（transport.calls=0）"
        }
        r.check("B8-4 SSID 匹配且绑定了账号 → 恰好 1 次认证请求，参数来自绑定凭据") {
            val (flow, transport) = flowWith("YTU-STU", mapOf("YTU-STU" to "中国移动"))
            val outcome = flow.run("YTU-STU")
            r.require(outcome is AuthFlowOutcome.Done, "应为 Done")
            r.requireEquals(1, transport.calls, "请求次数")
            val req = transport.lastRequest!!
            r.requireEquals(credential.username, req.username, "username")
            r.requireEquals("5", req.acId, "acId")
            r.requireEquals(true, (outcome as AuthFlowOutcome.Done).result.ok, "结果")
            "1 次请求，username=${req.username}，acId=${req.acId}"
        }
        r.check("B8-5 目标 SSID 为空（手动「立即登录」）→ 以当前 SSID 为准，匹配后发 1 次请求") {
            val (flow, transport) = flowWith("YTU-STU", mapOf("YTU-STU" to "中国移动"))
            val outcome = flow.run(null)
            r.require(outcome is AuthFlowOutcome.Done, "应为 Done")
            r.requireEquals(1, transport.calls, "请求次数")
            "1 次请求"
        }
        r.check("B8-6 绑定存在但凭据缺失 → 结构化失败（E_CONFIG），仍然零请求") {
            val transport = FakeTransport()
            val flow = AuthFlow(
                credentials = FakeCredentialLookup(mutableMapOf(), null),
                wifiMap = FakeWifiAccountLookup(mapOf("YTU-STU" to "不存在的账号")),
                wifiSnapshot = FakeWifiSnapshot("YTU-STU"),
                transport = transport
            )
            val outcome = flow.run("YTU-STU")
            val done = outcome as AuthFlowOutcome.Done
            r.requireEquals(false, done.result.ok, "ok")
            r.requireEquals(AuthCodes.E_CONFIG, done.result.code, "code")
            r.requireEquals(AuthFailure.CONFIG_MISSING, done.result.failure, "failure")
            r.requireEquals(0, transport.calls, "零请求")
            "零请求；状态区可显示：${done.result.msg}"
        }
        r.check("B8-7 跳过结果可转为结构化 AuthResult（状态区可见，失败不静默）") {
            val (flow, _) = flowWith("YTU-STU", mapOf("YTU-STU" to "中国移动"))
            flow.run("YTU-DORM")
            val result = flow.lastResult!!
            r.requireEquals(false, result.ok, "ok")
            r.requireContains(result.msg, "未发起认证", "msg")
            r.requireEquals("skip", result.stage, "stage")
            r.requireContains(result.code, "E_SKIP", "code")
            "lastResult=${result.code} / ${result.msg}"
        }
    }

    /* ---------------- UI 纯逻辑（B2/B5/权限顺序） ---------------- */

    private fun checkUiLogic(r: CheckRunner) {
        r.check("UI-1 B2 界面元素清单齐全（必需元素全部在，允许合法新增）") {
            val names = UiSpec.ELEMENTS.map { it.name }
            val required = listOf("账号输入", "密码输入", "登录方式二选一", "备注名", "WiFi 选择区", "权限说明与申请", "保存", "状态显示区", "立即登录")
            for (req in required) r.require(names.any { it.startsWith(req) }, "缺少界面元素：$req")
            // 口径：必需元素必须全部在（子集 + 下界），不写死总数——将来合法新增界面元素不应误报。
            // 必需控件 id 以 UiSpec.kt:24-34 的声明与 activity_main.xml 的实际控件 id 为准。
            val ids = UiSpec.ELEMENTS.flatMap { e -> e.viewId.split("/") }.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            val mustHaveIds = listOf("edit_username", "edit_password", "spinner_carrier", "edit_label", "ssid_list", "btn_use_current_wifi", "text_permission_notice", "btn_request_permission", "btn_save", "text_status", "btn_login_now")
            val missingIds = mustHaveIds.filterNot { it in ids }
            r.require(missingIds.isEmpty(), "缺少必需控件 id：$missingIds（现有：$ids）")
            r.require(UiSpec.ELEMENTS.size >= required.size, "元素数量下限：应 >= 必需项数（${required.size}），实际 ${UiSpec.ELEMENTS.size}")
            r.require(UiSpec.ELEMENTS.any { it.viewId == "edit_password" }, "缺密码输入框")
            UiSpec.ELEMENTS.joinToString("；") { it.toString() }
        }
        r.check("UI-2 登录方式二选一 = 烟台大学/中国移动，且值与冻结的 Carrier 常量一致") {
            r.requireEquals(listOf("烟台大学", "中国移动"), CarrierOption.displayNames(), "显示名")
            r.requireEquals("ytu", CarrierOption.YTU.value, "ytu")
            r.requireEquals("cmcc", CarrierOption.CMCC.value, "cmcc")
            r.requireEquals(Carrier.YTU, CarrierOption.YTU.value, "与冻结常量一致")
            r.requireEquals(Carrier.CMCC, CarrierOption.CMCC.value, "与冻结常量一致")
            r.requireEquals("5", Carrier.AC_ID, "acId 冻结值")
            "烟台大学=ytu / 中国移动=cmcc / acId=5"
        }
        r.check("UI-3 备注名默认自动生成（随登录方式变化，用户改过则不覆盖）") {
            val vm = newViewModel()
            r.requireEquals("烟台大学", vm.state.labelInput, "默认备注名")
            vm.selectCarrier(1)
            r.requireEquals("中国移动", vm.state.labelInput, "切换到中国移动后的默认备注名")
            vm.setLabel("宿舍宽带")
            vm.selectCarrier(0)
            r.requireEquals("宿舍宽带", vm.state.labelInput, "用户改过之后不应被覆盖")
            "默认生成 + 不覆盖用户输入"
        }
        r.check("UI-4 用户名按登录方式补运营商后缀（已含 @ 则原样）") {
            val vm = newViewModel()
            vm.setUsername("demo-student")
            vm.selectCarrier(1)
            r.requireEquals("demo-student@cmcc", vm.state.effectiveUsername(), "cmcc 后缀")
            vm.selectCarrier(0)
            r.requireEquals("demo-student@ytu", vm.state.effectiveUsername(), "ytu 后缀")
            vm.setUsername("demo-student@cmcc")
            r.requireEquals("demo-student@cmcc", vm.state.effectiveUsername(), "已含后缀不重复拼接")
            "后缀补全逻辑正确"
        }
        r.check("UI-5 WiFi 元素：系统列表 + 「用当前连接的 WiFi」快捷按钮") {
            val port = FakeWifiUiPort("YTU-STU", listOf("YTU-STU", "YTU-DORM"))
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            vm.refreshSsidList()
            r.requireEquals(listOf("YTU-STU", "YTU-DORM"), vm.state.ssidList, "系统列表")
            vm.useCurrentSsid()
            r.requireEquals("YTU-STU", vm.state.selectedSsid, "用当前连接的 WiFi")
            "列表=${vm.state.ssidList}，选中=${vm.state.selectedSsid}"
        }
        r.check("UI-6 权限顺序硬性固定：未先 markRationaleShown 就上报结果 → 提示顺序错误且不改状态") {
            val port = FakeWifiUiPort("YTU-STU", emptyList())
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            vm.onPermissionResult(true)
            r.require(port.calls.isEmpty(), "顺序错误时不应调用底层权限流程")
            r.requireContains(vm.state.noticeText, "顺序错误", "提示")
            "已拦截乱序调用：${vm.state.noticeText}"
        }
        r.check("UI-7 权限顺序实际调用序列 = beginPermissionRequest → markRationaleShown → onRequestResult") {
            val port = FakeWifiUiPort("YTU-STU", listOf("A", "B"))
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            vm.permissionExplanation()
            vm.beginPermissionRequest()
            vm.onPermissionResult(true)
            r.requireEquals(
                listOf("markRationaleShown", "onRequestResult(granted=true)"),
                port.calls, "调用序列"
            )
            "调用序列=${port.calls}"
        }
        r.check("UI-8 权限被拒 → 降级为只检测当前 WiFi 且界面显式提示（列表为空）") {
            val port = FakeWifiUiPort("YTU-STU", listOf("A", "B"))
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            vm.beginPermissionRequest()
            vm.onPermissionResult(false)
            r.requireEquals(WifiPermissionState.DENIED, vm.state.permissionState, "权限状态")
            r.requireEquals(true, vm.state.degraded, "降级标记")
            r.requireContains(vm.state.noticeText, "降级", "提示文案")
            vm.refreshSsidList()
            r.requireEquals(emptyList<String>(), vm.state.ssidList, "降级时列表为空")
            vm.useCurrentSsid()
            r.requireEquals("YTU-STU", vm.state.selectedSsid, "降级时仍能取当前 WiFi")
            "降级提示：${vm.state.noticeText}"
        }
        r.check("UI-9 降级原因来自已冻结的 WifiPermissionPolicy.capability") {
            val cap = WifiPermissionPolicy.capability(WifiPermissionState.DENIED)
            r.requireEquals(true, cap.canReadCurrentSsid, "仍可读当前 SSID")
            r.requireEquals(false, cap.canScanList, "不可扫描列表")
            r.requireContains(cap.degradedReason ?: "", "仅检测当前", "降级原因")
            cap.degradedReason ?: ""
        }
        r.check("UI-10 保存：产出 Credential（carrier/acId 正确）+ 目标 SSID") {
            val port = FakeWifiUiPort("YTU-STU", listOf("YTU-STU"))
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            vm.refreshSsidList()
            vm.setUsername("demo-student")
            vm.setPassword("Demo-Pass-1")
            vm.selectCarrier(1)
            vm.useCurrentSsid()
            val outcome = vm.save()
            r.require(outcome is SaveOutcome.Saved, "应为 Saved")
            val plan = (outcome as SaveOutcome.Saved).plan
            r.requireEquals("中国移动", plan.label, "label")
            r.requireEquals("demo-student@cmcc", plan.credential.username, "username")
            r.requireEquals("cmcc", plan.credential.carrier, "carrier")
            r.requireEquals("5", plan.credential.acId, "acId")
            r.requireEquals("YTU-STU", plan.targetSsid, "targetSsid")
            "Credential(label=${plan.label}, username=${plan.credential.username}, carrier=${plan.credential.carrier}, acId=${plan.credential.acId}) ↔ ${plan.targetSsid}"
        }
        r.check("UI-11 保存校验：空账号/空密码/未选 WiFi 均失败且写明原因（不静默）") {
            val port = FakeWifiUiPort("YTU-STU", emptyList())
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            val a = vm.save()
            r.require(a is SaveOutcome.Invalid, "空账号应失败")
            r.requireContains(vm.state.statusText, "账号", "提示")
            vm.setUsername("demo-student")
            vm.setPassword("Demo-Pass-1")
            val c = vm.save()
            r.require(c is SaveOutcome.Invalid, "未选 WiFi 应失败")
            r.requireContains(vm.state.statusText, "WiFi", "提示")
            "${(a as SaveOutcome.Invalid).message} / ${(c as SaveOutcome.Invalid).message}"
        }
        r.check("UI-12 状态区格式含时间 + 失败原因（B5 失败不静默）") {
            val port = FakeWifiUiPort("YTU-STU", emptyList())
            val fakeFlow = AuthFlow(
                credentials = FakeCredentialLookup(mutableMapOf("中国移动" to demoCredential()), demoCredential()),
                wifiMap = FakeWifiAccountLookup(emptyMap()),
                wifiSnapshot = FakeWifiSnapshot("YTU-STU"),
                transport = FakeTransport()
            )
            val vm = ConfigViewModel(port, object : LoginTrigger {
                override fun login(targetSsid: String?) = fakeFlow.run(targetSsid)
            }, clock = { 1_700_000_000_000L })
            vm.loginNow()
            r.requireEquals(false, vm.state.statusOk, "跳过 = 失败可见")
            r.requireContains(vm.state.statusText, "失败", "失败字样")
            r.requireContains(vm.state.statusText, "未绑定", "失败原因")
            r.require(Regex("\\[\\d{2}:\\d{2}:\\d{2}]").containsMatchIn(vm.state.statusText), "时间格式")
            vm.state.statusText
        }
        r.check("UI-13 立即登录命中匹配分支 → 状态区显示成功 + 时间 + 耗时") {
            val port = FakeWifiUiPort("YTU-STU", emptyList())
            val transport = FakeTransport()
            val flow = AuthFlow(
                credentials = FakeCredentialLookup(mutableMapOf("中国移动" to demoCredential()), demoCredential()),
                wifiMap = FakeWifiAccountLookup(mapOf("YTU-STU" to "中国移动")),
                wifiSnapshot = FakeWifiSnapshot("YTU-STU"),
                transport = transport,
                clock = { 0L }
            )
            val vm = ConfigViewModel(port, object : LoginTrigger {
                override fun login(targetSsid: String?) = flow.run(targetSsid)
            }, clock = { 1_700_000_000_000L })
            vm.selectSsid("YTU-STU")
            vm.loginNow()
            r.requireEquals(1, transport.calls, "请求次数")
            r.requireEquals(true, vm.state.statusOk, "成功")
            r.requireContains(vm.state.statusText, "成功", "成功字样")
            vm.state.statusText
        }
        r.check("UI-14 状态区字段覆盖：成功/失败/原因/时间/阶段/耗时（结构声明）") {
            // 口径：必需字段类别必须全部在（子集 + 下界），不写死类别总数——允许合法新增状态字段。
            val mustHaveCategories = listOf("成功或失败", "失败原因", "时间", "阶段", "耗时")
            val fields = UiSpec.STATUS_FIELDS
            for (cat in mustHaveCategories) r.require(fields.any { it.contains(cat) }, "状态区缺字段类别：$cat（现有：$fields）")
            r.require(fields.size >= mustHaveCategories.size, "字段类别数下限：应 >= ${mustHaveCategories.size}，实际 ${fields.size}")
            r.requireEquals(true, UiSpec.FAILURE_MUST_BE_VISIBLE, "失败必须可见")
            UiSpec.STATUS_FIELDS.joinToString("|")
        }
    }

    /* ---------------- 权限策略（冻结契约复用） ---------------- */

    private fun checkPermissionPolicy(r: CheckRunner) {
        r.check("PERM-1 权限顺序说明文案来源 = 冻结契约的 explainText") {
            val port = FakeWifiUiPort("YTU-STU", emptyList())
            val vm = ConfigViewModel(port, LoginTrigger.NOOP)
            r.requireEquals(port.explainText, vm.permissionExplanation(), "说明文案")
            r.requireContains(
                top.ytu.srunautologin.flow.PermissionText.ORDER,
                "markRationaleShown()", "顺序常量"
            )
            top.ytu.srunautologin.flow.PermissionText.ORDER
        }
        r.check("PERM-2 所需权限按 SDK 版本（API 26 无 / API 27-32 位置 / API 33+ 附近设备 + 位置）与冻结策略一致") {
            r.requireEquals(
                listOf(WifiPermissionPolicy.ACCESS_FINE_LOCATION),
                WifiPermissionPolicy.requiredPermissions(27), "API 27"
            )
            // 新口径（wifi-fix1 真机缺陷 R2 修订）：API 33+ 同时申请 NEARBY_WIFI_DEVICES 与 ACCESS_FINE_LOCATION。
            r.requireEquals(
                listOf(
                    WifiPermissionPolicy.NEARBY_WIFI_DEVICES,
                    WifiPermissionPolicy.ACCESS_FINE_LOCATION
                ),
                WifiPermissionPolicy.requiredPermissions(33), "API 33"
            )
            r.requireEquals(
                listOf(
                    WifiPermissionPolicy.NEARBY_WIFI_DEVICES,
                    WifiPermissionPolicy.ACCESS_FINE_LOCATION
                ),
                WifiPermissionPolicy.requiredPermissions(36), "API 36"
            )
            // ---- 保护断言（防回归，主 agent 要求）----
            // 依据：真机（Redmi Turbo 4 Pro / HyperOS 3 / Android 16）只授予 NEARBY_WIFI_DEVICES 时读不到 WiFi
            // （SSID 被系统遮罩为 <unknown ssid>、扫描列表为空）；官方 WifiManager.getScanResults() javadoc 逐字要求
            // "An app must hold ACCESS_FINE_LOCATION permission and ACCESS_WIFI_STATE permission in order to get valid results."
            for (sdk in listOf(33, 36)) {
                val required = WifiPermissionPolicy.requiredPermissions(sdk)
                r.require(
                    required.containsAll(
                        listOf(
                            WifiPermissionPolicy.NEARBY_WIFI_DEVICES,
                            WifiPermissionPolicy.ACCESS_FINE_LOCATION
                        )
                    ),
                    "保护断言：API$sdk 所需权限必须同时包含 NEARBY_WIFI_DEVICES 与 ACCESS_FINE_LOCATION" +
                        "（依据：真机实测只授予 NEARBY 时读不到 WiFi + getScanResults() javadoc 要求 ACCESS_FINE_LOCATION）；" +
                        "实际=< $required >"
                )
            }
            r.requireEquals(emptyList<String>(), WifiPermissionPolicy.requiredPermissions(26), "API 26")
            "冻结策略（API 33/36 = NEARBY_WIFI_DEVICES + ACCESS_FINE_LOCATION，依据真机实测 + getScanResults() javadoc）"
        }
    }

    private fun newViewModel(): ConfigViewModel {
        val port = FakeWifiUiPort("YTU-STU", listOf("YTU-STU"))
        return ConfigViewModel(port, LoginTrigger.NOOP)
    }
}
