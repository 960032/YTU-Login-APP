package top.ytu.srunautologin.storagecheck

import top.ytu.srunautologin.net.DefaultWifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiScanEntry
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.net.WifiSource
import top.ytu.srunautologin.storage.Carrier
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.storage.CredentialRepository
import top.ytu.srunautologin.storage.FileKeyValueStore
import top.ytu.srunautologin.storage.FixedSecretKeyProvider
import top.ytu.srunautologin.storage.InMemoryKeyValueStore
import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.SecureStore
import top.ytu.srunautologin.storage.SecureStoreException
import top.ytu.srunautologin.storage.WifiAccountMap
import java.io.File

/**
 * 存储层 / WiFi 感知层的离线核对逻辑（纯 JVM，零第三方依赖）。
 *
 * 同一份逻辑被两处复用：
 *  1) verify-common-storage → jvm-check-storage（本机离线运行，产出真实原始输出）；
 *  2) app/src/test（JUnit，供有 Android SDK + 网络的环境跑 `./gradlew :app:test`）。
 *
 * 所有数据均为**合成假数据**，不含任何真实凭据。
 */
object StorageChecks {

    data class Item(val id: String, val title: String, val passed: Boolean, val evidence: String)

    /** JVM 测试用固定 KEK（32 字节）；真机由 Android Keystore 提供，绝不用此密钥。 */
    private val TEST_KEY = ByteArray(32) { ((it * 7 + 11) and 0xFF).toByte() }

    private const val FAKE_LABEL = "中国移动-宿舍"
    private const val FAKE_LABEL2 = "烟台大学-图书馆"
    private const val FAKE_USER = "20230000000"
    private const val FAKE_PASSWORD = "P@ssw0rd-测试-9f3a"
    private const val UNKNOWN = "<unknown ssid>"

    // ------------------------------- 极简断言器 -------------------------------

    private fun assertEquals(msg: String, expected: Any?, actual: Any?) {
        if (expected != actual) throw AssertionError("$msg：期望 <$expected>，实际 <$actual>")
    }

    private fun assertTrue(msg: String, cond: Boolean) {
        if (!cond) throw AssertionError(msg)
    }

    private fun assertFalse(msg: String, cond: Boolean) {
        if (cond) throw AssertionError(msg)
    }

    private inline fun <reified T : Throwable> expectThrow(msg: String, block: () -> Unit): T {
        try {
            block()
        } catch (t: Throwable) {
            if (t is T) return t
            throw AssertionError("$msg：实际抛出 ${t::class.simpleName}，期望 ${T::class.simpleName}")
        }
        throw AssertionError("$msg：期望抛 ${T::class.simpleName}，但正常返回了")
    }

    private fun hex(bytes: ByteArray, limit: Int = 24): String =
        bytes.take(limit).joinToString(" ") { "%02x".format(it) } + if (bytes.size > limit) " ..." else ""

    /** 朴素子串检索：返回首次命中的下标，未命中返回 -1。 */
    private fun indexOfSub(hay: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || hay.size < needle.size) return -1
        outer@ for (i in 0..(hay.size - needle.size)) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    private fun contains(hay: ByteArray, needle: ByteArray): Boolean = indexOfSub(hay, needle) >= 0

    // ------------------------------- 测试替身 -------------------------------

    private class FakeWifiSource(
        private val enabled: Boolean = true,
        private val current: String? = "YTU-Student",
        private val entries: List<WifiScanEntry> = emptyList(),
        private val throwOnCurrent: Boolean = false,
        private val throwOnScan: Boolean = false
    ) : WifiSource {
        override fun isWifiEnabled(): Boolean = enabled
        override fun currentSsidRaw(): String? {
            if (throwOnCurrent) throw SecurityException("模拟：无权限读取当前 SSID")
            return current
        }
        override fun scanSsidEntries(): List<WifiScanEntry> {
            if (throwOnScan) throw SecurityException("模拟：无权限扫描")
            return entries
        }
    }

    private fun newStore(): SecureStore = SecureStore(FixedSecretKeyProvider(TEST_KEY))

    private fun fakeCredential(label: String = FAKE_LABEL): Credential =
        Credential(label, FAKE_USER, FAKE_PASSWORD, Carrier.CMCC, Carrier.AC_ID)

    // ------------------------------- 主入口 -------------------------------

    fun runAll(workDir: File): List<Item> {
        if (!workDir.exists()) workDir.mkdirs()
        val out = ArrayList<Item>()

        fun item(id: String, title: String, body: () -> String) {
            try {
                out.add(Item(id, title, true, body()))
            } catch (t: Throwable) {
                out.add(Item(id, title, false, "失败: ${t::class.simpleName}: ${t.message}"))
            }
        }

        // ================= A. 存储层：AES/GCM 加解密（B7） =================

        item("C1", "加解密往返：字符串明文 → 密文 → 原文") {
            val s = newStore()
            val ct = s.encryptToBase64String(FAKE_PASSWORD)
            val back = s.decryptFromBase64String(ct)
            assertEquals("往返不一致", FAKE_PASSWORD, back)
            "明文=< $FAKE_PASSWORD > 密文Base64=< ${ct.take(28)}... >（共 ${ct.length} 字符）解密=< $back >"
        }

        item("C2", "加解密往返：全 0x00–0xFF 字节序列（二进制安全）") {
            val s = newStore()
            val plain = ByteArray(256) { it.toByte() }
            val back = s.decrypt(s.encrypt(plain))
            assertTrue("往返不一致", plain.contentEquals(back))
            "明文长度=${plain.size} 首8字节=<${hex(plain, 8)}> 解密后长度=${back.size}"
        }

        item("C3", "随机 IV：同一明文两次加密密文不同") {
            val s = newStore()
            val a = s.encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            val b = s.encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            assertFalse("两次密文完全相同（IV 未随机化）", a.contentEquals(b))
            val ivA = a.copyOfRange(2, 14)
            val ivB = b.copyOfRange(2, 14)
            assertFalse("两次 IV 相同", ivA.contentEquals(ivB))
            "密文A=<${hex(a, 16)}> 密文B=<${hex(b, 16)}> IV-A=<${hex(ivA, 12)}> IV-B=<${hex(ivB, 12)}>"
        }

        item("C4", "篡改密文末字节 → 解密失败（GCM 认证）") {
            val s = newStore()
            val ct = s.encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            val tampered = ct.copyOf()
            tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
            val e = expectThrow<SecureStoreException>("篡改密文后未抛异常") {
                s.decrypt(tampered)
            }
            assertTrue("原始密文与篡改密文相同", !ct.contentEquals(tampered))
            "篡改位置=末尾 异常类型=${e::class.simpleName} 异常消息=<${e.message}> 原因=${e.cause?.javaClass?.simpleName}"
        }

        item("C5", "篡改 IV → 解密失败") {
            val s = newStore()
            val ct = s.encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            val tampered = ct.copyOf()
            tampered[3] = (tampered[3].toInt() xor 0xFF).toByte()
            val e = expectThrow<SecureStoreException>("篡改 IV 后未抛异常") { s.decrypt(tampered) }
            "异常=<${e::class.simpleName}> 消息=<${e.message}>"
        }

        item("C6", "篡改头部（magic/版本）→ 解密失败") {
            val s = newStore()
            val ct = s.encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            val badMagic = ct.copyOf().also { it[0] = 0x58 }
            val badVersion = ct.copyOf().also { it[1] = 0x09 }
            val e1 = expectThrow<SecureStoreException>("magic 被篡改后未抛异常") { s.decrypt(badMagic) }
            val e2 = expectThrow<SecureStoreException>("版本被篡改后未抛异常") { s.decrypt(badVersion) }
            "magic异常=<${e1.message}>；版本异常=<${e2.message}>"
        }

        item("C7", "密文被截断 → 解密失败") {
            val s = newStore()
            val ct = s.encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            val truncated = ct.copyOfRange(0, ct.size - 1)
            val e = expectThrow<SecureStoreException>("截断后未抛异常") { s.decrypt(truncated) }
            "原长度=${ct.size} 截断后=${truncated.size} 异常=<${e.message}>"
        }

        item("C8", "换一把 KEK 解同一密文 → 解密失败（密钥不匹配）") {
            val ct = newStore().encrypt(FAKE_PASSWORD.toByteArray(Charsets.UTF_8))
            val other = SecureStore(FixedSecretKeyProvider(ByteArray(32) { (it + 1).toByte() }))
            val e = expectThrow<SecureStoreException>("换密钥后未抛异常") { other.decrypt(ct) }
            "异常=<${e::class.simpleName}> 消息=<${e.message}>"
        }

        item("C9", "B7 落盘字节中不含明文密码/用户名（含检索器自检）") {
            val kv = InMemoryKeyValueStore()
            val repo = CredentialRepository(newStore(), kv)
            repo.upsert(fakeCredential())
            val bytes = repo.persistedBlobBytes() ?: throw AssertionError("未产生落盘数据")
            val pw = FAKE_PASSWORD.toByteArray(Charsets.UTF_8)
            val user = FAKE_USER.toByteArray(Charsets.UTF_8)
            // 检索器自检（防止「检索器永远返回 -1」造成的假阴性）
            assertTrue("检索器自检失败：明文控制组未命中", contains(("xx" + FAKE_PASSWORD).toByteArray(Charsets.UTF_8), pw))
            assertFalse("落盘字节包含明文密码！", contains(bytes, pw))
            assertFalse("落盘字节包含明文用户名！", contains(bytes, user))
            "落盘字节长度=${bytes.size} 前16字节=<${hex(bytes, 16)}> 密码命中下标=${indexOfSub(bytes, pw)} 用户名命中下标=${indexOfSub(bytes, user)}"
        }

        item("C10", "落盘格式：Base64 解码后以 'S'(0x53)+版本 0x01 开头，且非明文可读") {
            val kv = InMemoryKeyValueStore()
            val repo = CredentialRepository(newStore(), kv)
            repo.upsert(fakeCredential())
            val blob = repo.persistedBlob() ?: throw AssertionError("无落盘内容")
            val bytes = SecureStore.base64ToBytes(blob)
            assertEquals("magic 错误", 0x53, bytes[0].toInt() and 0xFF)
            assertEquals("版本错误", 0x01, bytes[1].toInt() and 0xFF)
            val printable = blob.count { it.code in 0x20..0x7E || it.code > 0x7F }
            assertTrue("落盘内容疑似为纯明文（含中文字符）", !blob.contains("中国移动"))
            "Base64 头 32 字符=<${blob.take(32)}> 解码后头4字节=<${hex(bytes, 4)}> 全长=${bytes.size} 可见字符数=$printable"
        }

        item("C11", "CredentialRepository：增 / 改 / 查 / 删") {
            val repo = CredentialRepository(newStore(), InMemoryKeyValueStore())
            assertTrue("新增应返回 true", repo.upsert(fakeCredential()))
            repo.upsert(fakeCredential(FAKE_LABEL2))
            assertEquals("条数错误", 2, repo.list().size)
            assertFalse("覆盖同名应返回 false", repo.upsert(fakeCredential().copy(password = "NewPwd-1")))
            assertEquals("覆盖后条数错误", 2, repo.list().size)
            assertEquals("覆盖后密码未更新", "NewPwd-1", repo.find(FAKE_LABEL)?.password)
            assertEquals("按 label 查询失败", FAKE_LABEL2, repo.find(FAKE_LABEL2)?.label)
            assertTrue("删除失败", repo.delete(FAKE_LABEL2))
            assertEquals("删除后条数错误", 1, repo.list().size)
            assertFalse("删除不存在的记录应返回 false", repo.delete("不存在"))
            "最终条数=${repo.list().size} 剩余label=<${repo.list().map { it.label }}>"
        }

        item("C12", "B3/选中凭据：写入 → 读回 → 模拟重启（新实例读同一份磁盘数据）") {
            val dir = File(workDir, "restart-cred")
            dir.deleteRecursively()
            val repo1 = CredentialRepository(newStore(), FileKeyValueStore(dir))
            repo1.upsert(fakeCredential())
            repo1.select(FAKE_LABEL)
            repo1.upsert(fakeCredential(FAKE_LABEL2))
            val files1 = dir.listFiles()?.map { it.name }?.sorted() ?: emptyList()

            val repo2 = CredentialRepository(newStore(), FileKeyValueStore(dir))   // 模拟重启
            val restored = repo2.list()
            val sel = repo2.selected()
            assertEquals("重启后条数不符", 2, restored.size)
            assertEquals("重启后密码不符", FAKE_PASSWORD, repo2.find(FAKE_LABEL)?.password)
            assertEquals("重启后登录方式不符", Carrier.CMCC, repo2.find(FAKE_LABEL)?.carrier)
            assertEquals("重启后 acId 不符", "5", repo2.find(FAKE_LABEL)?.acId)
            assertEquals("重启后选中项丢失", FAKE_LABEL, sel?.label)
            "落盘文件=<${files1}> 重启后条数=${restored.size} 选中=<${sel?.label}>"
        }

        item("C13", "删除凭据时一并清理「选中」与 WiFi 绑定") {
            val dir = File(workDir, "delete-clean")
            dir.deleteRecursively()
            val kv = FileKeyValueStore(dir)
            val repo = CredentialRepository(newStore(), kv)
            val map = WifiAccountMap(kv)
            repo.upsert(fakeCredential())
            repo.select(FAKE_LABEL)
            map.bind("YTU-Student", FAKE_LABEL)
            map.bind("YTU-WiFi-5G", FAKE_LABEL)
            assertTrue("删除失败", repo.delete(FAKE_LABEL))
            val cleaned = map.unbindByLabel(FAKE_LABEL)
            assertEquals("清理的 SSID 数不符", 2, cleaned)
            assertEquals("选中项未清理", null, repo.selectedLabel())
            assertEquals("绑定未清空", 0, map.mapping().size)
            "清理 SSID 数=$cleaned 剩余映射=${map.mapping()}"
        }

        item("C14", "B3 WifiAccountMap：写入 → 读回 → 模拟重启后仍在") {
            val dir = File(workDir, "restart-map")
            dir.deleteRecursively()
            val m1 = WifiAccountMap(FileKeyValueStore(dir))
            m1.bind("YTU-Student", FAKE_LABEL)
            m1.bind("中国移动-宿舍-WiFi", FAKE_LABEL2)
            val onDisk = FileKeyValueStore(dir).getString(WifiAccountMap.KEY_MAP) ?: throw AssertionError("未落盘")

            val m2 = WifiAccountMap(FileKeyValueStore(dir))   // 模拟重启
            assertEquals("重启后映射条数不符", 2, m2.mapping().size)
            assertEquals("重启后 label 不符", FAKE_LABEL, m2.labelFor("YTU-Student"))
            assertEquals("重启后中文 SSID 不符", FAKE_LABEL2, m2.labelFor("中国移动-宿舍-WiFi"))
            assertEquals("未知 SSID 应返回 null", null, m2.labelFor("别人的热点"))
            "落盘原文=< $onDisk > 重启后 mapping=< ${m2.mapping()} >"
        }

        item("C15", "WifiAccountMap：多对一 / 覆盖写 / unbind / ssidsOf") {
            val m = WifiAccountMap(InMemoryKeyValueStore())
            m.bind("A", FAKE_LABEL)
            m.bind("B", FAKE_LABEL)
            m.bind("C", FAKE_LABEL2)
            m.bind("A", FAKE_LABEL2)          // 覆盖
            assertEquals("一个 label 应可对应多个 SSID", listOf("B"), m.ssidsOf(FAKE_LABEL))
            assertEquals("覆盖写失败", listOf("A", "C"), m.ssidsOf(FAKE_LABEL2))
            assertTrue("unbind 失败", m.unbind("B"))
            assertFalse("重复 unbind 应返回 false", m.unbind("B"))
            "映射=${m.mapping()} ssidsOf($FAKE_LABEL2)=${m.ssidsOf(FAKE_LABEL2)}"
        }

        item("C16", "转义：label 含 制表符/反斜杠/换行/中文 也能无损往返") {
            val weird = "含\t制表\\符 与\n换行-中文"
            val repo = CredentialRepository(newStore(), InMemoryKeyValueStore())
            repo.upsert(Credential(weird, FAKE_USER, "p\\w\td", Carrier.YTU, Carrier.AC_ID))
            val back = repo.find(weird) ?: throw AssertionError("未能按原 label 找回")
            assertEquals("label 往返失真", weird, back.label)
            assertEquals("密码往返失真", "p\\w\td", back.password)
            "label 长度=${weird.length} → 往返后长度=${back.label.length} 相等=OK；密码=<${back.password}>"
        }

        item("C17", "冻结口径：acId 必须是字符串 \"5\"；carrier 只允许 ytu/cmcc") {
            val ok = fakeCredential()
            assertEquals("acId 值错误", "5", ok.acId)
            assertTrue("acId 不是 String", ok.acId is String)
            val e1 = expectThrow<IllegalArgumentException>("非法 acId 未抛异常") {
                Credential("x", FAKE_USER, "p", Carrier.YTU, "1")
            }
            val e2 = expectThrow<IllegalArgumentException>("非法 carrier 未抛异常") {
                Credential("x", FAKE_USER, "p", "unicom", Carrier.AC_ID)
            }
            assertEquals("显示名错误", "中国移动", Carrier.displayName(Carrier.CMCC))
            "acId=<${ok.acId}> carrier=<${ok.carrier}> 异常1=<${e1.message}> 异常2=<${e2.message}>"
        }

        item("C18", "Credential.toString 不含密码（防止密码进日志）") {
            val text = fakeCredential().toString()
            assertFalse("toString 泄漏了密码", text.contains(FAKE_PASSWORD))
            assertTrue("toString 未打码", text.contains("***"))
            "toString=< $text >"
        }

        item("C19", "密文不可解时仓库不崩溃：list() 返回空列表") {
            val kv = InMemoryKeyValueStore()
            val repo = CredentialRepository(newStore(), kv)
            repo.upsert(fakeCredential())
            kv.putString(CredentialRepository.KEY_BLOB, "U0" + SecureStore.bytesToBase64(ByteArray(40)))
            val list = repo.list()
            assertEquals("损坏密文应返回空列表", 0, list.size)
            "损坏后 list().size=${list.size} 未抛异常=OK"
        }

        // ================= B. WiFi 感知与权限降级（N3） =================

        item("C20", "权限策略：API 26 → NOT_REQUIRED；27–32 → FINE_LOCATION；33+ → NEARBY_WIFI_DEVICES") {
            val p = WifiPermissionPolicy
            assertEquals("API26 所需权限", emptyList<String>(), p.requiredPermissions(26))
            assertEquals("API27 所需权限", listOf(p.ACCESS_FINE_LOCATION), p.requiredPermissions(27))
            assertEquals("API32 所需权限", listOf(p.ACCESS_FINE_LOCATION), p.requiredPermissions(32))
            assertEquals("API33 所需权限", listOf(p.NEARBY_WIFI_DEVICES), p.requiredPermissions(33))
            assertEquals("API36 所需权限", listOf(p.NEARBY_WIFI_DEVICES), p.requiredPermissions(36))
            assertEquals("API26 状态", WifiPermissionState.NOT_REQUIRED, p.state(26, emptySet()))
            assertEquals("API27 未授权", WifiPermissionState.DENIED, p.state(27, emptySet()))
            assertEquals("API27 已授权", WifiPermissionState.GRANTED, p.state(27, setOf(p.ACCESS_FINE_LOCATION)))
            assertEquals("API33 未授权", WifiPermissionState.DENIED, p.state(33, emptySet()))
            assertEquals("API33 仅 NEARBY", WifiPermissionState.GRANTED, p.state(33, setOf(p.NEARBY_WIFI_DEVICES)))
            assertEquals("API33 仅 FINE（等效）", WifiPermissionState.GRANTED, p.state(33, setOf(p.ACCESS_FINE_LOCATION)))
            assertEquals("API36 仅 NEARBY", WifiPermissionState.GRANTED, p.state(36, setOf(p.NEARBY_WIFI_DEVICES)))
            "API26/27/32/33/36 所需权限与状态分支全部符合预期"
        }

        item("C21", "N3 降级：权限 DENIED 时 scanSsidList 返回空列表且不抛异常") {
            val flow = DefaultWifiPermissionFlow(33, emptySet())          // 未授予 NEARBY_WIFI_DEVICES
            assertEquals("前置状态应为 DENIED", WifiPermissionState.DENIED, flow.state())
            val core = WifiSnapshotCore(
                FakeWifiSource(entries = listOf(WifiScanEntry("A", -40), WifiScanEntry("B", -70))),
                flow
            )
            val list = core.scanSsidList()
            assertEquals("降级后应返回空列表", 0, list.size)
            assertEquals("降级后 canScanList 应为 false", false, core.capability().canScanList)
            assertTrue("降级原因缺失", core.capability().degradedReason?.isNotEmpty() == true)
            "scanSsidList()=< $list > 异常=无 capability=< ${core.capability()} >"
        }

        item("C22", "N3 降级：DENIED 时 currentSsid 仍走降级路径，返回当前连接的 WiFi") {
            val flow = DefaultWifiPermissionFlow(33, emptySet())
            val core = WifiSnapshotCore(FakeWifiSource(current = "YTU-Student"), flow)
            assertEquals("降级路径应仍能读到当前 SSID", "YTU-Student", core.currentSsid())
            assertEquals("降级后 canReadCurrentSsid 应为 true", true, core.capability().canReadCurrentSsid)
            val noWifi = WifiSnapshotCore(FakeWifiSource(enabled = false, current = "YTU-Student"), flow)
            assertEquals("WiFi 关闭时应返回 null", null, noWifi.currentSsid())
            "DENIED 时 currentSsid=< ${core.currentSsid()} >；WiFi 关闭时=< ${noWifi.currentSsid()} >"
        }

        item("C23", "GRANTED/NOT_REQUIRED：去重 + 按信号降序 + 过滤空 SSID 与 <unknown ssid>") {
            val granted = DefaultWifiPermissionFlow(33, setOf(WifiPermissionPolicy.NEARBY_WIFI_DEVICES))
            val entries = listOf(
                WifiScanEntry("弱信号热点", -85),
                WifiScanEntry("强信号热点", -35),
                WifiScanEntry("强信号热点", -30),      // 同一 SSID 重复，应保留最强
                WifiScanEntry("", -20),                // 空 SSID
                WifiScanEntry(UNKNOWN, -10),           // 占位串
                WifiScanEntry(" 中信号热点 ", -60)
            )
            val core = WifiSnapshotCore(FakeWifiSource(entries = entries), granted)
            val list = core.scanSsidList()
            assertEquals("去重/排序/过滤结果不符", listOf("强信号热点", "中信号热点", "弱信号热点"), list)
            val notRequired = WifiSnapshotCore(FakeWifiSource(entries = entries), DefaultWifiPermissionFlow(26))
            assertEquals("API26 应可扫描", list, notRequired.scanSsidList())
            "原始 6 条 → 输出 < $list >"
        }

        item("C24", "权限流程顺序：未先说明用途就处理申请结果 → 抛 IllegalStateException") {
            val flow = DefaultWifiPermissionFlow(33, emptySet())
            val e = expectThrow<IllegalStateException>("顺序颠倒未抛异常") {
                flow.onRequestResult(WifiPermissionRequestOutcome.GRANTED)
            }
            assertEquals("说明前状态应为 DENIED", WifiPermissionState.DENIED, flow.state())
            assertTrue("explainText 为空", flow.explainText.length > 10)
            flow.markRationaleShown()
            assertTrue("markRationaleShown 未生效", flow.isRationaleShown())
            val afterGrant = flow.onRequestResult(WifiPermissionRequestOutcome.GRANTED)
            assertEquals("授权后状态", WifiPermissionState.GRANTED, afterGrant)
            "未说明即申请 → <${e::class.simpleName}: ${e.message}>；说明后授权 → $afterGrant"
        }

        item("C25", "权限流程：拒绝后的降级能力 + 从设置页回到应用时重新同步") {
            val flow = DefaultWifiPermissionFlow(33, setOf(WifiPermissionPolicy.NEARBY_WIFI_DEVICES))
            flow.markRationaleShown()
            val afterDeny = flow.onRequestResult(WifiPermissionRequestOutcome.DENIED)
            assertEquals("拒绝后状态", WifiPermissionState.DENIED, afterDeny)
            val core = WifiSnapshotCore(FakeWifiSource(current = "YTU-Student", entries = listOf(WifiScanEntry("A", -40))), flow)
            assertEquals("拒绝后不扫描", 0, core.scanSsidList().size)
            assertEquals("拒绝后仍读当前 SSID", "YTU-Student", core.currentSsid())
            flow.syncGrantedPermissions(setOf(WifiPermissionPolicy.NEARBY_WIFI_DEVICES))
            assertEquals("重新同步后状态", WifiPermissionState.GRANTED, flow.state())
            assertEquals("重新同步后可扫描", 1, core.scanSsidList().size)
            "拒绝 → scan=<0> current=<YTU-Student>；重新同步 → $afterDeny→${flow.state()} scan=${core.scanSsidList()}"
        }

        item("C26", "系统抛 SecurityException 时不崩溃：返回 null / 空列表") {
            val granted = DefaultWifiPermissionFlow(33, setOf(WifiPermissionPolicy.NEARBY_WIFI_DEVICES))
            val core = WifiSnapshotCore(
                FakeWifiSource(throwOnCurrent = true, throwOnScan = true),
                granted
            )
            assertEquals("currentSsid 应降级为 null", null, core.currentSsid())
            assertEquals("scanSsidList 应降级为空列表", 0, core.scanSsidList().size)
            "source 抛 SecurityException → currentSsid=null、scanSsidList=[] 且无异常逃逸"
        }

        item("C27", "端到端：SSID → 凭据 label → 当前选中凭据（后续任务调用链）") {
            val kv = InMemoryKeyValueStore()
            val repo = CredentialRepository(newStore(), kv)
            val map = WifiAccountMap(kv)
            repo.upsert(fakeCredential().copy(carrier = Carrier.CMCC))
            repo.upsert(fakeCredential(FAKE_LABEL2).copy(carrier = Carrier.YTU))
            map.bind("YTU-Student", FAKE_LABEL2)
            applySelected(repo, map, "YTU-Student")

            val resolved = repo.selected()
            assertEquals("解析出的凭据错误", FAKE_LABEL2, resolved?.label)
            assertEquals("登录方式错误", Carrier.YTU, resolved?.carrier)
            assertEquals("acId 错误", "5", resolved?.acId)
            applySelected(repo, map, "别人的热点")
            assertEquals("未匹配 SSID 时不应改变选中项", FAKE_LABEL2, repo.selected()?.label)
            "SSID=<YTU-Student> → label=<${resolved?.label}> → 登录方式=<${Carrier.displayName(resolved!!.carrier)}> acId=<${resolved.acId}>"
        }

        return out
    }

    /** 后续 UI/调度任务要用的「按当前 SSID 选中凭据」纯逻辑（此处即接口契约示例）。 */
    fun applySelected(repo: CredentialRepository, map: WifiAccountMap, ssid: String?): Boolean {
        val label = map.labelFor(ssid) ?: return false
        return repo.select(label)
    }
}