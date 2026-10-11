package top.ytu.srunautologin.client

import org.junit.Assert.assertTrue
import org.junit.Test
import top.ytu.srunautologin.clientcheck.ClientChecks
import java.io.File

/**
 * 认证客户端 / 编排 / UI 纯逻辑的 JUnit 包装（有 Gradle 时执行：`./gradlew :app:test`）。
 *
 * 核对逻辑与离线核对程序（jvm-check-client）**共用同一份** ClientChecks，
 * 避免两份实现漂移；本文件只负责把每条结论转成断言。
 *
 * 本机无 Android SDK / 网络，无法执行本测试；离线通道见 artifacts/android-client/build-log.txt。
 */
class AuthFlowAndUiTest {

    /** android-app 项目根目录（Gradle 的工作目录是 app/，故向上跳一级）。 */
    private val appRoot: File = generateSequence(File("").absoluteFile) { it.parentFile }
        .take(4)
        .firstOrNull { File(it, "app/src/main/java/top/ytu/srunautologin/auth").isDirectory }
        ?: File("..").absoluteFile

    @Test
    fun `认证客户端与编排与UI 纯逻辑全部核对项通过`() {
        val results = ClientChecks.runAll(appRoot)
        val failed = results.filter { !it.passed }
        val message = if (failed.isEmpty()) {
            "全部 ${results.size} 项通过"
        } else {
            "失败 ${failed.size}/${results.size} 项：" +
                failed.joinToString("; ") { "${it.id} → ${it.detail}" }
        }
        assertTrue(message, failed.isEmpty())
    }
}
