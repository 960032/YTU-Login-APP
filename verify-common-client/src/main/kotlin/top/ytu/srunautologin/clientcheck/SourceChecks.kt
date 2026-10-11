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
        r.check("SRC-4 AndroidManifest：新增权限只有 INTERNET / ACCESS_NETWORK_STATE，无无障碍服务") {
            r.require(manifest.isFile, "缺少 AndroidManifest.xml")
            val text = manifest.readText()
            val permissions = Regex("""android:name="(android\.permission\.[A-Z_]+)"""")
                .findAll(text).map { it.groupValues[1] }.toList()
            r.require(permissions.contains("android.permission.INTERNET"), "缺少 INTERNET")
            r.require(permissions.contains("android.permission.ACCESS_NETWORK_STATE"), "缺少 ACCESS_NETWORK_STATE")
            val forbidden = listOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.POST_NOTIFICATIONS",
                "android.permission.QUERY_ALL_PACKAGES"
            )
            val present = forbidden.filter { it in permissions }
            r.require(present.isEmpty(), "出现不应有的权限：$present")
            r.require(!text.contains("accessibilityservice", ignoreCase = true), "不应出现无障碍服务声明")
            "权限清单（按出现顺序）：${permissions.joinToString()} "
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
