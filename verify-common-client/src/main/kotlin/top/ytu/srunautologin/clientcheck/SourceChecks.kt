package top.ytu.srunautologin.clientcheck

import java.io.File
import java.security.MessageDigest

/**
 * 源码/资源结构核对（B2 界面元素、N4 权限、B10 密码学单一来源）。
 *
 * 输入为项目根目录（artifacts/android-app）——只读文本，不修改任何文件。
 * 只有当目录不存在时对应核对项才判为不可用（会明确写出原因，不静默通过）。
 */

/**
 * assertion-fix2/A：**稳健定位 android-app 项目根目录**（不再把「项目根」当固定相对路径）。
 *
 * 背景：本工作区路径含中文（`...\YTU校园网\...`）。③ 套核对入口 `ClientCheckMain.kt:14`
 * 用的是 `File(".")` 这类相对路径，只有「当前工作目录恰好是 artifacts/android-app」时才成立。
 * 本函数把「定位」这一步显式化，且**不做任何转义/编码假设**：
 * 全程只用 `java.io.File` 的原生 Unicode 路径（Java 内部走 Windows 宽字符 API），
 * 不拼码点、不做 percent-encoding、不依赖控制台代码页。
 *
 * 解析顺序：
 *  ① 显式传入的根（若其自带 `settings.gradle.kts` + `app/src/main/AndroidManifest.xml` 两个标记）；
 *  ② 从当前工作目录**逐级向上**查找带上述标记的目录；
 *  ③ 从当前工作目录向上最多 5 层，逐层探测 `artifacts/android-app`、`android-app`
 *     （覆盖「工作目录是工作区根」与「工作目录是 artifacts/ 下某个子目录」两种情况）；
 *  ④ 宽松兜底：只要含 `app/src/main/AndroidManifest.xml` 就接受。
 *
 * 都找不到 → 返回 null（由调用方**明确报错**，不静默通过）。
 */
fun resolveAndroidAppRoot(explicit: File? = null): File? {
    val marker = "app/src/main/AndroidManifest.xml"

    fun looksLikeRoot(d: File?): Boolean =
        d != null && d.isDirectory && File(d, "settings.gradle.kts").isFile && File(d, marker).isFile

    fun looksLikeRootLoose(d: File?): Boolean =
        d != null && d.isDirectory && File(d, marker).isFile

    // ① 显式传入且带完整标记
    if (looksLikeRoot(explicit)) return explicit!!.absoluteFile

    // ② 从当前工作目录逐级向上
    var up: File? = File("").absoluteFile
    while (up != null) {
        if (looksLikeRoot(up)) return up
        up = up.parentFile
    }

    // ③ 已知相对位置（含「工作区根 → artifacts/android-app」）
    var base: File? = File("").absoluteFile
    var level = 0
    while (base != null && level <= 5) {
        for (cand in listOf("artifacts/android-app", "android-app")) {
            val c = File(base, cand)
            if (looksLikeRoot(c)) return c.absoluteFile
        }
        base = base.parentFile
        level++
    }

    // ④ 宽松兜底
    if (looksLikeRootLoose(explicit)) return explicit!!.absoluteFile
    var loose: File? = File("").absoluteFile
    while (loose != null) {
        if (looksLikeRootLoose(loose)) return loose
        loose = loose.parentFile
    }
    return null
}

object SourceChecks {

    /** auth 包源码中不应出现的「自写密码学」痕迹。 */
    private val FORBIDDEN_CRYPTO_TRACES = listOf(
        "MessageDigest", "Mac.getInstance", "SecretKeySpec", "Base64", "xEncode"
    )

    /**
     * SRC-4 权限白名单：允许出现在 AndroidManifest 里的 `uses-permission`（顺序不限）。
     *
     * 修订记录（**只更新已被需求变更推翻的口径，其余一条不动**）：
     *  - T15：写死 2 条（INTERNET + ACCESS_NETWORK_STATE）。
     *  - T16：新增 RECEIVE_BOOT_COMPLETED（B4 开机自启）→ 原断言过时，本口径改为
     *    「白名单（⊆，挡住悄悄扩权）+ 黑名单（∩ = ∅，守住 N4/B9 最小权限红线）」双重检查。
     *  - assertion-fix2（需求变更：每日 6:00 精确唤醒 + 待机常驻通知）：
     *    该功能**必须**声明 POST_NOTIFICATIONS（API 33+ 才能显示通知）、
     *    FOREGROUND_SERVICE + FOREGROUND_SERVICE_DATA_SYNC（API 34+ 前台服务「类型 ↔ 类型权限」强制配对）、
     *    SCHEDULE_EXACT_ALARM（精确闹钟）。旧白名单 7 条因此再次过时 → 扩为 11 条；
     *    并把 POST_NOTIFICATIONS / FOREGROUND_SERVICE 从黑名单移除（它们是本需求的**必要**权限，
     *    不再是「危险权限」）。**真正危险的权限仍在黑名单里，一条未动**（见下）。
     */
    private val ALLOWED_PERMISSIONS = listOf(
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        // ↓ assertion-fix2 新增：morning1「每日 6:00 精确唤醒 + 待机常驻通知」的四条必需权限
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
        "android.permission.SCHEDULE_EXACT_ALARM"
    )

    /**
     * SRC-4 权限黑名单：一旦出现即判 FAIL（无障碍服务、悬浮窗、全量包查询、
     * 通话记录/短信/通讯录、外部存储）。
     *
     * 这是护栏本体，**不得删除**——即使白名单已经把它挡住，仍要独立断言一次，
     * 保证有人误删白名单条目时红线检查依然生效（两层互为保险）。
     *
     * assertion-fix2 变更：**仅移出** POST_NOTIFICATIONS 与 FOREGROUND_SERVICE
     * （它们是新需求的必要权限，不能既在白名单又在黑名单）；其余 **8 条一条未动**。
     */
    private val FORBIDDEN_PERMISSIONS = listOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE"
    )

    // ---------------- SRC-3 冻结文件基线（本次修订） ----------------

    /**
     * SRC-3 的基线副本在核对工程内的资源路径。
     *
     * 来历与验收依据：该文件是 `app/src/main/java/top/ytu/srunautologin/crypto/SrunCrypto.kt` 的
     * **原样字节复制**（复制当时两侧 SHA256 均为
     * `0AE0AD94E61A4271811B1DAA9C352331F3FE48FD30F9ED4D2F665E6D54FFE723`，16347 字节），
     * 而那份代码正是**第 ① 套密码学行为核对 52/52 通过的同一份文件**，因此具备验收依据。
     */
    private const val BASELINE_RESOURCE = "top/ytu/srunautologin/clientcheck/SrunCrypto.kt"

    /** 核对工程源码树的兜底相对路径（classpath 取不到资源时使用，仍然是同一份只读基线副本）。 */
    private const val BASELINE_FALLBACK_PATH =
        "verify-common-client/src/main/resources/top/ytu/srunautologin/clientcheck/SrunCrypto.kt"

    /** 基线副本**原始字节**（未规范化）的 SHA256 小写十六进制，用于防止基线副本被偷偷改动。 */
    private const val BASELINE_RAW_SHA256 =
        "0ae0ad94e61a4271811b1daa9c352331f3fe48fd30f9ed4d2f665e6d54ffe723"

    /**
     * 读取 SRC-3 的基线副本文本。
     *
     * 优先走 classpath 资源（编译产物里 `jvm-out/classes/top/ytu/.../clientcheck/SrunCrypto.kt`），
     * 取不到时退回核对工程源码树内的同名资源文件；两处都不存在才判「无法核对」（明确报错，不静默通过）。
     */
    private fun loadCryptoBaselineText(): String {
        javaClass.classLoader.getResourceAsStream(BASELINE_RESOURCE)?.use { stream ->
            return stream.readBytes().toString(Charsets.UTF_8)
        }
        val fallback = File(BASELINE_FALLBACK_PATH)
        if (fallback.isFile) return fallback.readText()
        throw AssertionError(
            "取不到 SRC-3 基线副本（classpath 资源 $BASELINE_RESOURCE，" +
                "兜底路径 ${fallback.absolutePath} 也不存在）"
        )
    }

    /** 统一行尾：CRLF 与裸 CR 一律折成 LF，使比对与空白规范化无关。 */
    private fun normalizeNewlines(text: String): String = text.replace("\r\n", "\n").replace("\r", "\n")

    /** 计算字节串的 SHA256，返回小写十六进制。 */
    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    fun run(r: CheckRunner, appRootArg: File) {
        // assertion-fix2/A：先把「项目根」稳健解析出来。
        // 入口（ClientCheckMain.kt:14）可能只传了 `File(".")`；这里不再假设它就是项目根。
        val appRoot = resolveAndroidAppRoot(appRootArg)
        if (appRoot == null) {
            r.check("SRC-0 定位 android-app 项目根目录（稳健解析，assertion-fix2/A）") {
                r.require(
                    false,
                    "无法定位 android-app 项目根目录：调用方传入 ${appRootArg.absolutePath}；" +
                        "已尝试「逐级向上查找含 settings.gradle.kts + app/src/main/AndroidManifest.xml 的目录」" +
                        "与「向上 5 层探测 artifacts/android-app」（全程只走 java.io.File 原生 Unicode 路径，无转义假设）"
                )
                "【不可达：上面 require 已抛断言异常】"
            }
            return
        }
        r.check("SRC-0 定位 android-app 项目根目录（稳健解析，assertion-fix2/A）") {
            "解析结果=${appRoot.absolutePath}（调用方传入 ${appRootArg.absolutePath}）；" +
                "判据：该目录同时含 settings.gradle.kts 与 app/src/main/AndroidManifest.xml"
        }

        val authDir = File(appRoot, "app/src/main/java/top/ytu/srunautologin/auth")
        val uiDir = File(appRoot, "app/src/main/java/top/ytu/srunautologin/ui")
        val manifest = File(appRoot, "app/src/main/AndroidManifest.xml")
        val layout = File(appRoot, "app/src/main/res/layout/activity_main.xml")
        val strings = File(appRoot, "app/src/main/res/values/strings.xml")
        val cryptoFile = File(appRoot, "app/src/main/java/top/ytu/srunautologin/crypto/SrunCrypto.kt")

        r.check("SRC-1 auth 包内不含自写密码学实现（B10：唯一来源是 SrunCrypto）") {
            val files = authDir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }?.toList() ?: emptyList()
            r.require(files.isNotEmpty(), "未找到 auth 包源文件：${authDir.absolutePath}")
            val hits = ArrayList<String>()
            var codeLines = 0
            for (f in files) {
                for ((i, line) in f.readText().lines().withIndex()) {
                    val code = line.trim()
                    // 跳过注释行（KDoc/行注释），只检查可执行代码
                    if (code.startsWith("*") || code.startsWith("//") || code.startsWith("/*")) continue
                    codeLines++
                    for (trace in FORBIDDEN_CRYPTO_TRACES) {
                        if (code.contains(trace)) hits.add("${f.name}:${i + 1}: $trace")
                    }
                }
            }
            r.require(hits.isEmpty(), "auth 包代码行中出现自写算法痕迹：$hits")
            r.require(authDir.listFiles()!!.any { it.name == "SrunAuthClient.kt" }, "缺少 SrunAuthClient.kt")
            "已扫描 ${files.size} 个 auth 源文件的 $codeLines 行代码，未出现 ${FORBIDDEN_CRYPTO_TRACES.joinToString()}"
        }
        r.check("SRC-2 auth 包源码确实调用 SrunCrypto 的 4 个入口（调用点证据）") {
            val builder = File(authDir, "SrunRequestBuilder.kt")
            r.require(builder.isFile, "缺少 SrunRequestBuilder.kt")
            val lines = builder.readText().lines()
            val expected = listOf(
                "SrunCrypto.hmacMd5(",
                "SrunCrypto.passwordField(",
                "SrunCrypto.infoField(",
                "SrunCrypto.chksum("
            )
            val report = expected.joinToString("；") { call ->
                // 只认代码行（跳过注释里的说明文字）
                val idx = lines.indexOfFirst { line ->
                    val code = line.trim()
                    code.contains(call) && !code.startsWith("*") && !code.startsWith("//")
                }
                r.require(idx >= 0, "未找到调用点 $call")
                "$call @ SrunRequestBuilder.kt:${idx + 1}"
            }
            report
        }
        r.check("SRC-3 已冻结的 SrunCrypto.kt 未改（与已验收基线副本「规范化行尾后」逐字节比对；不用裸 SHA256）") {
            r.require(cryptoFile.isFile, "缺少 SrunCrypto.kt")
            val actualText = cryptoFile.readText()
            val baselineText = loadCryptoBaselineText()

            // ① 基线副本自身不得被改动：按原始字节比对记录的 SHA256。
            //    这里对**基线副本**固定哈希是可行的（基线副本是冻结文件，不随本源码编辑而变化），
            //    同时也就避免了「把基线副本一起改掉以掩盖真实改动」这条绕过路径。
            val baselineRawHex = sha256Hex(baselineText.toByteArray(Charsets.UTF_8))
            r.requireEquals(
                BASELINE_RAW_SHA256, baselineRawHex,
                "基线副本 SrunCrypto.kt 原始字节 SHA256 已变（基线副本只读，不得修改；如需更新基线须重新走验收）"
            )

            // ② 核心判据：双方都先把行尾统一为 LF，再逐字节（UTF-8 编码后）比对。
            //    任何一行内容的改动都会让两侧不一致 → FAIL；
            //    CRLF/LF 差异被规范化吸收 → 不再误报。
            val actualNorm = normalizeNewlines(actualText)
            val baselineNorm = normalizeNewlines(baselineText)
            val actualNormHex = sha256Hex(actualNorm.toByteArray(Charsets.UTF_8))
            val baselineNormHex = sha256Hex(baselineNorm.toByteArray(Charsets.UTF_8))
            r.requireEquals(
                baselineNormHex, actualNormHex,
                "SrunCrypto.kt 内容已被改动（规范化行尾后逐字节不一致；未改动时两者必须相等）"
            )
            "规范化行尾后与基线逐字节一致：规范化SHA256=${actualNormHex.take(16)}…；" +
                "文件原始字节=${cryptoFile.readBytes().size}（行尾符不影响判定）；" +
                "基线原始SHA256=${baselineRawHex.take(16)}…"
        }
        r.check("SRC-4 AndroidManifest 权限：实际集合 ⊆ 白名单，且 ∩ 黑名单 = ∅（N4/B9 最小权限）") {
            r.require(manifest.isFile, "缺少 AndroidManifest.xml")
            val text = manifest.readText()
            // 注释用于「权限台账」说明（本次修订教训：旧版对注释做 contains 检查会误判），先剥注释只检查真正生效的 XML。
            val declText = text.replace(Regex("""<!--[\s\S]*?-->"""), "")
            // 权限台账 = 全部 <uses-permission> 的 android:name（含换行的两行写法，如 NEARBY_WIFI_DEVICES）。
            // 注意：不把 <service android:permission="..."> 计入——那是「谁能绑定本服务」的限制，不是应用申请的权限。
            val permissions = Regex("""<uses-permission[^>]*?android:name="(android\.permission\.[A-Z_]+)"""")
                .findAll(declText).map { it.groupValues[1] }.toList()
            val actual = permissions.toSet()

            // 必须项：联网与网络状态判断是本应用存在的意义，缺了就是功能坏了（不是权限最小化问题）。
            r.require("android.permission.INTERNET" in actual, "缺少 INTERNET")
            r.require("android.permission.ACCESS_NETWORK_STATE" in actual, "缺少 ACCESS_NETWORK_STATE")

            // 断言 ①：实际权限集合 ⊆ 白名单（挡「悄悄扩权」）。
            val notAllowed = (actual - ALLOWED_PERMISSIONS.toSet()).sorted()
            r.require(
                notAllowed.isEmpty(),
                "出现白名单之外的权限（如确为基准卡所需，应先评审再登记进 ALLOWED_PERMISSIONS）：$notAllowed"
            )

            // 断言 ②：实际权限集合 ∩ 黑名单 = ∅（守 N4/B9 红线）。
            val black = (actual intersect FORBIDDEN_PERMISSIONS.toSet()).sorted()
            r.require(black.isEmpty(), "出现黑名单权限（N4/B9 禁止项）：$black")

            r.require(!declText.contains("<accessibilityservice", ignoreCase = true), "不应出现无障碍服务声明")

            // 组件级 android:permission 属性（如 service 的 BIND_JOB_SERVICE）不是「申请权限」，但也是权限面，
            // 同样用白名单守住：只允许 BIND_JOB_SERVICE 这一条（限制谁能绑定本应用的服务）。
            val componentPerms = Regex("""<[a-z]+[^>]*?\sandroid:permission="([^"]+)"""")
                .findAll(declText).map { it.groupValues[1] }.toSet()
            val badComponentPerms = (componentPerms - setOf("android.permission.BIND_JOB_SERVICE")).sorted()
            r.require(badComponentPerms.isEmpty(), "组件上出现白名单之外的 android:permission 属性：$badComponentPerms")

            "白名单 ${ALLOWED_PERMISSIONS.size} 条 / 黑名单 ${FORBIDDEN_PERMISSIONS.size} 条；" +
                "实际权限 ${actual.size} 条（按出现顺序）：${permissions.joinToString()}；白名单外 0 条；黑名单命中 0 条；" +
                "组件级 android:permission=${componentPerms.joinToString().ifEmpty { "（无）" }}"
        }
        r.check("SRC-5 AndroidManifest：MainActivity 已注册、exported=true、LAUNCHER") {
            val text = manifest.readText()
            r.requireContains(text, "top.ytu.srunautologin.ui.MainActivity", "Activity 类名")
            r.requireContains(text, "android:exported=\"true\"", "exported")
            r.requireContains(text, "android.intent.category.LAUNCHER", "LAUNCHER")
            "MainActivity 注册正确"
        }
        r.check("SRC-6 布局：B2 要求的控件 id 全部存在，密码框为 textPassword，无第三方控件") {
            r.require(layout.isFile, "缺少 activity_main.xml")
            val xml = layout.readText()
            val ids = Regex("""android:id="@\+id/([a-z_0-9]+)"""")
                .findAll(xml).map { it.groupValues[1] }.toList()
            val required = listOf(
                "edit_username", "edit_password", "spinner_carrier", "edit_label",
                "btn_use_current_wifi", "ssid_list", "btn_request_permission",
                "btn_save", "text_status", "btn_login_now"
            )
            val missing = required.filter { it !in ids }
            r.require(missing.isEmpty(), "布局缺少控件：$missing")
            r.requireContains(xml, "android:inputType=\"textPassword\"", "密码框输入类型")
            val forbiddenViews = listOf("androidx.", "com.google.android.material", "ComposeView", "androidx.compose")
            val bad = forbiddenViews.filter { xml.contains(it) }
            r.require(bad.isEmpty(), "布局引用了第三方/Compose 控件：$bad")
            "控件 id 数量=${ids.size}，全部必需 id 就位；密码框 inputType=textPassword"
        }
        r.check("SRC-7 布局中密码框 EditText 的 id 与 textPassword 属性在同一节点") {
            val xml = layout.readText()
            val node = Regex("""<EditText[\s\S]*?</EditText>|<EditText[^>]*/>""")
                .findAll(xml).map { it.value }.firstOrNull { it.contains("edit_password") }
                ?: throw AssertionError("未找到 edit_password 节点")
            r.requireContains(node, "android:inputType=\"textPassword\"", "同节点属性")
            node.replace(Regex("\\s+"), " ").trim()
        }
        r.check("SRC-8 strings.xml 文案齐全（元素 1–9 所需字符串均存在）") {
            r.require(strings.isFile, "缺少 strings.xml")
            val xml = strings.readText()
            val names = Regex("""<string name="([a-z_0-9]+)"""").findAll(xml).map { it.groupValues[1] }.toList()
            val required = listOf(
                "app_name", "label_username", "hint_username", "label_password", "label_carrier",
                "label_label", "label_wifi", "btn_use_current_wifi", "btn_request_permission",
                "btn_save", "status_initial", "btn_login_now", "degraded_prefix", "degraded_no_list"
            )
            val missing = required.filter { it !in names }
            r.require(missing.isEmpty(), "strings.xml 缺少：$missing")
            "字符串条目数=${names.size}"
        }
        r.check("SRC-9 manifest 引用的所有 @style/@string 均在同一工程内定义（避免运行期缺资源）") {
            val text = manifest.readText()
            val themes = File(appRoot, "app/src/main/res/values/themes.xml")
            val stringsXml = strings.readText()
            val styleRefs = Regex("""@style/([A-Za-z_0-9.]+)""").findAll(text).map { it.groupValues[1] }.toList()
            for (ref in styleRefs) {
                r.require(themes.isFile && themes.readText().contains("name=\"$ref\""), "缺少 style：$ref")
            }
            val stringRefs = Regex("""@string/([a-z_0-9]+)""").findAll(text).map { it.groupValues[1] }.toList()
            for (ref in stringRefs) {
                r.require(stringsXml.contains("name=\"$ref\""), "缺少 string：$ref")
            }
            "已校验 style=${styleRefs} string=${stringRefs}"
        }
        r.check("SRC-10 UI 层只依赖系统 View/框架类（不引入 AppCompat/Compose 等第三方 UI 库）") {
            val files = uiDir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }?.toList() ?: emptyList()
            r.require(files.isNotEmpty(), "未找到 ui 包源文件：${uiDir.absolutePath}")
            val hits = ArrayList<String>()
            for (f in files) {
                val text = f.readText()
                for (marker in listOf("androidx.", "androidx.compose", "com.google.android.material")) {
                    if (text.contains(marker)) hits.add("${f.name}: $marker")
                }
            }
            r.require(hits.isEmpty(), "ui 包引用第三方 UI 库：$hits")
            "已扫描 ${files.size} 个 ui 源文件，未引用 androidx/compose/material"
        }
    }
}
