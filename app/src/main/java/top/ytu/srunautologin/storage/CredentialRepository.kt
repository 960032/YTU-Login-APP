package top.ytu.srunautologin.storage

/**
 * 凭据仓库：多条 [Credential] 的增删查改 + 「当前选中」凭据。
 *
 * 持久化：**整份凭据列表**被 [SecureStore] 加密后以 Base64 存进 [KeyValueStore] 的一个 key。
 * 落盘内容永远是密文，明文密码不落盘（B7）。
 *
 * 记录格式（仅存在于密文内部，明文段）：
 *   `label \t username \t password \t carrier \t acId`，记录之间用 '\n' 分隔。
 *
 * 「当前选中」的 label 存在独立 key（label 本身不是秘密），指向列表中的一条记录。
 *
 * 本文件为纯 JVM 代码，可离线编译与测试。
 */
class CredentialRepository(
    private val secureStore: SecureStore,
    private val kv: KeyValueStore
) {
    companion object {
        const val KEY_BLOB = "credentials_v1"
        const val KEY_SELECTED = "selected_label_v1"
        const val FIELD_SEPARATOR = "\t"
        const val RECORD_SEPARATOR = "\n"
    }

    /** 读取全部凭据；无数据或密文不可解（密钥变更/被篡改）时返回空列表，不抛异常。 */
    fun list(): List<Credential> {
        val blob = kv.getString(KEY_BLOB) ?: return emptyList()
        val plain = try {
            secureStore.decryptFromBase64String(blob)
        } catch (e: SecureStoreException) {
            // 加密层不可用（密钥被删除/失效、密文被篡改）时**降级为「无凭据」而不是抛出**：本方法在 UI 渲染与
            // 登录判定的同步栈上被调用，抛出去就是闪退。这里同时留下可复查的日志痕迹，避免「静默消失」。
            // 只改读取侧的降级，不动写入侧契约——写失败仍由 save()/upsert() 抛给调用方（UI 捕获并显示可见错误）。
            java.util.logging.Logger.getLogger("SrunAutoLogin").warning(
                "凭据读取失败，降级为「无凭据」：" + e.javaClass.simpleName + ": " + e.message
            )
            return emptyList()
        }
        if (plain.isEmpty()) return emptyList()
        return plain.split(RECORD_SEPARATOR)
            .filter { it.isNotEmpty() }
            .mapNotNull { line ->
                val f = TextEscaping.splitFields(line)
                if (f.size < 5) return@mapNotNull null
                runCatching {
                    Credential(
                        label = f[0],
                        username = f[1],
                        password = f[2],
                        carrier = f[3],
                        acId = f[4]
                    )
                }.getOrNull()
            }
    }

    fun find(label: String): Credential? = list().firstOrNull { it.label == label }

    /**
     * 新增或按 label 覆盖；返回 true 表示新增，false 表示覆盖已有。
     *
     * 异常契约（行为未改动，仅明确写出）：加密不可用时 [SecureStore.encryptToBase64String] 抛
     * [SecureStoreException] 并**原样透传**给调用方，由 UI 捕获后显示可见错误（保存失败不再闪退）。
     */
    fun upsert(credential: Credential): Boolean {
        val all = list().toMutableList()
        val idx = all.indexOfFirst { it.label == credential.label }
        return if (idx >= 0) {
            all[idx] = credential
            save(all)
            false
        } else {
            all.add(credential)
            save(all)
            true
        }
    }

    fun delete(label: String): Boolean {
        val all = list().toMutableList()
        val removed = all.removeAll { it.label == label }
        if (removed) {
            save(all)
            if (selectedLabel() == label) kv.remove(KEY_SELECTED)
        }
        return removed
    }

    fun clear() {
        kv.remove(KEY_BLOB)
        kv.remove(KEY_SELECTED)
    }

    fun selectedLabel(): String? = kv.getString(KEY_SELECTED)

    /** 选中某条凭据；label 不存在时返回 false 且不改变现状。 */
    fun select(label: String): Boolean {
        if (find(label) == null) return false
        kv.putString(KEY_SELECTED, label)
        return true
    }

    fun selected(): Credential? = selectedLabel()?.let { find(it) }

    /** 供 UI 显示的「当前选中备注名 + 登录方式」，避免把密码带进 UI 状态之外的层。 */
    fun selectedSummary(): String? = selected()?.let { "${it.label}（${Carrier.displayName(it.carrier)}）" }

    private fun save(all: List<Credential>) {
        val plain = all.joinToString(RECORD_SEPARATOR) { c ->
            TextEscaping.joinFields(listOf(c.label, c.username, c.password, c.carrier, c.acId))
        }
        kv.putString(KEY_BLOB, secureStore.encryptToBase64String(plain))
    }

    /** 测试/审计用：原始落盘 Base64 字符串（内容为密文）。 */
    fun persistedBlob(): String? = kv.getString(KEY_BLOB)

    /** 测试/审计用：原始落盘字节（内容为密文）。 */
    fun persistedBlobBytes(): ByteArray? =
        persistedBlob()?.let { SecureStore.base64ToBytes(it) }
}