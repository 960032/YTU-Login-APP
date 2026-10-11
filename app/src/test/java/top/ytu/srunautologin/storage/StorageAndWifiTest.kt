package top.ytu.srunautologin.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import top.ytu.srunautologin.net.DefaultWifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiScanEntry
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.net.WifiSource
import top.ytu.srunautologin.storagecheck.StorageChecks
import java.io.File

/**
 * 存储层 / WiFi 感知层的 JUnit 4 单元测试（零第三方运行时依赖）。
 *
 * 本机（无 Android SDK、无网络、无 JUnit 构件）**无法执行**本文件；
 * 实际执行记录见 artifacts/android-storage/build-log.txt（走 jvm-check-storage 纯 JVM 运行器，
 * 与这里共用同一份核对逻辑 verify-common-storage/src/main/kotlin/.../StorageChecks.kt）。
 *
 * 全部数据为合成假数据，不含任何真实凭据。
 */
class StorageAndWifiTest {

    private val testKey = ByteArray(32) { ((it * 7 + 11) and 0xFF).toByte() }
    private val password = "P@ssw0rd-测试-9f3a"
    private val label = "中国移动-宿舍"

    private fun store() = SecureStore(FixedSecretKeyProvider(testKey))

    private class FakeSource(
        private val current: String? = "YTU-Student",
        private val entries: List<WifiScanEntry> = emptyList()
    ) : WifiSource {
        override fun isWifiEnabled(): Boolean = true
        override fun currentSsidRaw(): String? = current
        override fun scanSsidEntries(): List<WifiScanEntry> = entries
    }

    /** B7：加解密往返（含随机 IV）。 */
    @Test
    fun b7_roundTripKeepsPlaintext() {
        val s = store()
        val cipher = s.encryptToBase64String(password)
        assertEquals(password, s.decryptFromBase64String(cipher))
    }

    /** B7：同一明文两次加密的密文不同（IV 随机）。 */
    @Test
    fun b7_samePlaintextProducesDifferentCiphertext() {
        val s = store()
        val a = s.encrypt(password.toByteArray(Charsets.UTF_8))
        val b = s.encrypt(password.toByteArray(Charsets.UTF_8))
        assertFalse("两次密文相同，IV 未随机化", a.contentEquals(b))
    }

    /** B7：篡改密文后解密必须失败（GCM 认证）。 */
    @Test
    fun b7_tamperedCiphertextFailsAuthentication() {
        val s = store()
        val cipher = s.encrypt(password.toByteArray(Charsets.UTF_8))
        val tampered = cipher.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
        try {
            s.decrypt(tampered)
            fail("篡改密文后解密成功，GCM 认证失效")
        } catch (expected: SecureStoreException) {
            assertNotNull(expected.message)
        }
    }

    /** B7：序列化后的字节里不得出现明文密码。 */
    @Test
    fun b7_persistedBytesContainNoPlaintextPassword() {
        val repo = CredentialRepository(store(), InMemoryKeyValueStore())
        repo.upsert(Credential(label, "20230000000", password, Carrier.CMCC, Carrier.AC_ID))
        // 【编译错误修复】原写法 `repo.persistedBlobBytes() ?: fail("未产生落盘数据")!!`：
        // JUnit 的 fail(String) 是 Java void 方法（Kotlin 侧为 Unit），elvis 表达式
        // `ByteArray? ?: Unit` 的公共超类型被推断为 Any，bytes 的类型随之成为 Any，
        // 到下一行把它当 ByteArray 传参时才在调用点报
        // "Argument type mismatch: actual type is 'Any', but 'ByteArray' was expected"（CI 报错 82:44 即此实参）。
        // 改为 `run { fail(...); error(...) }`：分支末端是 Nothing 类型，elvis 结果类型回到 ByteArray；
        // fail(...) 的调用与失败信息逐字保留，断言语义未变。
        val bytes = repo.persistedBlobBytes() ?: run { fail("未产生落盘数据"); error("unreachable: fail 未抛出") }
        assertFalse("落盘字节包含明文密码", byteArrayContains(bytes, password.toByteArray(Charsets.UTF_8)))
    }

    /** B3：WiFi ↔ 账号映射持久化，重启（新建实例读同一份存储）后仍在。 */
    @Test
    fun b3_wifiAccountMapSurvivesRestart() {
        val dir = File(System.getProperty("java.io.tmpdir"), "srun-junit-wifi-map-" + System.nanoTime())
        try {
            WifiAccountMap(FileKeyValueStore(dir)).bind("YTU-Student", label)
            val afterRestart = WifiAccountMap(FileKeyValueStore(dir))
            assertEquals(label, afterRestart.labelFor("YTU-Student"))
        } finally {
            dir.deleteRecursively()
        }
    }

    /** N3：权限 DENIED → 不扫描列表（返回空、不抛异常），但仍读当前连接的 WiFi。 */
    @Test
    fun n3_deniedPermissionScansNothingButStillReadsCurrentSsid() {
        val flow = DefaultWifiPermissionFlow(33, emptySet())
        assertEquals(WifiPermissionState.DENIED, flow.state())
        val core = WifiSnapshotCore(FakeSource(entries = listOf(WifiScanEntry("A", -40))), flow)
        assertEquals(0, core.scanSsidList().size)
        assertEquals("YTU-Student", core.currentSsid())
        assertFalse(core.capability().canScanList)
        assertTrue(core.capability().canReadCurrentSsid)
    }

    /** 复用离线核对逻辑（同一份 StorageChecks），保证两条路径不漂移。 */
    @Test
    fun allOfflineChecksPass() {
        val dir = File(System.getProperty("java.io.tmpdir"), "srun-junit-storage-checks")
        val items = StorageChecks.runAll(dir)
        val failed = items.filter { !it.passed }
        assertTrue(
            "离线核对失败项: " + failed.joinToString("; ") { "${it.id}: ${it.evidence}" },
            failed.isEmpty()
        )
        assertTrue("核对项过少（${items.size}）", items.size >= 27)
    }

    /** 字节序列包含判定。函数名刻意避开 Kotlin 内建的 `ByteArray.contains(element: Byte)`，
     *  以免读者/后续修改把它误当成内建成员方法（与本次编译错误无因果关系，属防御性改名）。 */
    private fun byteArrayContains(hay: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..(hay.size - needle.size)) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}