package top.ytu.srunautologin.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * SrunCrypto 的 JVM 单元测试（JUnit 4，零第三方运行时依赖）。
 *
 * 判据：testvectors/vectors.json —— 全部由 Node 版 artifacts/srun-impl/srun-crypto.js 现算产出（仅合成数据）。
 * 核对逻辑复用 verify-common/src/main/kotlin/.../VectorChecks.kt（由 app/build.gradle.kts 追加为 test 源目录）。
 *
 * 注意：本机（无 Android SDK、无网络、无 JUnit 构件）无法执行本文件；实际执行记录见
 * artifacts/kotlin-crypto/build-log.txt（走 jvm-check 纯 JVM 运行器，同一份核对逻辑）。
 */
class SrunCryptoTest {

    private fun vectorsFile(): File {
        val candidates = listOf(
            File("testvectors/vectors.json"),            // 从仓库根运行
            File("../testvectors/vectors.json"),         // Gradle 单元测试默认工作目录是 app/
            File("app/testvectors/vectors.json"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: throw AssertionError(
                "找不到 testvectors/vectors.json，已尝试: " + candidates.joinToString(" | ") { it.absolutePath }
            )
    }

    /** B10：7 个公开函数与 Node 版逐字符一致。 */
    @Test
    fun allVectorsMatchNodeReference() {
        val result = VectorChecks.run(vectorsFile())
        val message = "共 ${result.total} 条向量，失败 ${result.failures.size} 条：\n" +
            result.failures.joinToString("\n") { "[${it.category} #${it.index}] ${it.detail}" }
        assertTrue(message, result.failures.isEmpty())
        assertTrue("向量条数过少（${result.total}），疑似 vectors.json 未生成", result.total >= 50)
    }

    /** B10 边界：base64Encode 对字符码 > 255 必须抛错（对齐参考实现 _getbyte）。 */
    @Test
    fun base64EncodeRejectsCharCodesAbove255() {
        for (bad in listOf("ab\u0100", "你好", "ab\uD83D\uDE00")) {
            val thrown = try {
                SrunCrypto.base64Encode(bad)
                null
            } catch (t: Throwable) {
                t
            }
            assertTrue("字符码 > 255 时必须抛错，输入=${bad.length} 字符", thrown != null)
            assertTrue(
                "异常信息应包含 INVALID_CHARACTER_ERR，实际=${thrown!!.message}",
                (thrown.message ?: "").contains("INVALID_CHARACTER_ERR")
            )
        }
    }

    /** B10 关键分支：hmacMd5 空 key 必须退化为 md5(msg)（blueimp md5 v2.10.0 行为）。 */
    @Test
    fun hmacMd5EmptyKeyDegradesToPlainMd5() {
        assertEquals(SrunCrypto.md5("TestPassword123"), SrunCrypto.hmacMd5("", "TestPassword123"))
        assertEquals(SrunCrypto.md5(""), SrunCrypto.hmacMd5("", ""))
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", SrunCrypto.hmacMd5("", ""))
    }

    /** 公开 API 冻结：签名不得改名/改型（编译期约束，写出来便于后续任务对照）。 */
    @Test
    fun publicApiIsFrozen() {
        val md5: (String) -> String = SrunCrypto::md5
        val sha1: (String) -> String = SrunCrypto::sha1
        val hmac: (String, String) -> String = SrunCrypto::hmacMd5
        val b64: (String) -> String = SrunCrypto::base64Encode
        val pwd: (String, String) -> String = SrunCrypto::passwordField
        val chk: (String, String, String, String, String, Int, Int, String) -> String = SrunCrypto::chksum
        val info: (String, String, String, String, String) -> String = SrunCrypto::infoField
        assertTrue(md5("").isNotEmpty() && sha1("").isNotEmpty() && hmac("k", "m").isNotEmpty() &&
            b64("A").isNotEmpty() && pwd("p", "t").isNotEmpty() && info("u", "p", "i", "5", "t").isNotEmpty())
        assertEquals(40, chk("t", "u", "h", "5", "i", 200, 1, "").length)
        assertEquals("{MD5}", pwd("p", "t").substring(0, 5))
        assertEquals("{SRBX1}", info("u", "p", "i", "5", "t").substring(0, 7))
    }
}
