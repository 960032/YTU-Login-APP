package top.ytu.srunautologin.clientcheck

import java.io.File

/**
 * 源码/资源结构核对（B2 界面元素、N4 权限、B10 密码学单一来源）。
 *
 * 输入为项目根目录（artifacts/android-app）——只读文本，不修改任何文件。
 * 只有当目录不存在时对应核对项才判为不可用（会明确写出原因，不静默通过）。
 */
object SourceChecks {

    /** auth 包源码中不应出现的「自写密码学」痕迹。 */
    private val FORBIDDEN_CRYPTO_TRACES = listOf(
        "MessageDigest", "Mac.getInstance", "SecretKeySpec", "Base64", "xEncode"
    )

    /**
     * SRC-4 权限白名单：允许出现在 AndroidManifest 里的 `uses-permission`，恰好这 7 条（顺序不限）。
     *
     * 修订说明（第 ③ 套核对 57 项中唯一失败项的修正）：原断言写于 T15，当时 manifest 权限确实只有
     * INTERNET + ACCESS_NETWORK_STATE；T16 为满足基准卡 B4「开机后无需人工操作自动认证」正确新增了
     * RECEIVE_BOOT_COMPLETED，于是原「写死两条」的断言过时，产生误报。本口径改为
     * 「白名单（⊆，挡住悄悄扩权）+ 黑名单（∩ = ∅，守住 N4/B9 最小权限红线）」双重检查。
     */
    private val ALLOWED_PERMISSIONS = listOf(
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.RECEIVE_BOOT_COMPLETED"
    )

    /**
     * SRC-4 权限黑名单：一旦出现即判 FAIL（无障碍服务、悬浮窗、全量包查询、
     * 通话记录/短信/通讯录、通知、前台服务、外部存储）。
     *
     * 这是护栏本体，**不得删除**——即使白名单已经把它挡住，仍要独立断言一次，
     * 保证有人误删白名单条目时红线检查依然生效（两层互为保险）。
     */
    private val FORBIDDEN_PERMISSIONS = listOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE"
    )

    fun run(r: CheckRunner, appRoot: File) {
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
        r.check("SRC-3 已冻结的 SrunCrypto.kt 未改（SHA256 = B7A36DD2…98F9）") {
            r.require(cryptoFile.isFile, "缺少 SrunCrypto.kt")
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val hex = digest.digest(cryptoFile.readBytes()).joinToString("") { "%02X".format(it) }
            r.requireEquals("B7A36DD28CC6C8C7D42F1A1FEEFB4F455B4F837FB55187C38FA40E3B51B098F9", hex, "SrunCrypto.kt SHA256")
            "SHA256=$hex"
        }
        r.check("SRC-4 AndroidManifest 权限：实际集合 ⊆ 白名单（7 条）且 ∩ 黑名单 = ∅（N4/B9 最小权限）") {
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
                "text_permission_notice", "btn_save", "text_status", "btn_login_now"
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
