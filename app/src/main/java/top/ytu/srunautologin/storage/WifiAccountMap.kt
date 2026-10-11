package top.ytu.srunautologin.storage

/**
 * WiFi SSID ↔ 凭据 label 的对应关系，持久化在 [KeyValueStore]。
 *
 * 对应关系口径（需求原文：「wifi-账号的对应记忆和选择功能」）：
 *  - **多对一**：多个 SSID（如 `YTU-WiFi` 与 `YTU-WiFi-5G`）可以绑定到同一条凭据；
 *  - **一对一上限**：单个 SSID 至多绑定一条凭据，重复 [bind] 为覆盖式写入；
 *  - SSID 大小写敏感（Android 返回的 SSID 原样保存）。
 *
 * 落盘内容为 SSID 与 label 的文本映射（这两者都不是密码，不加密；密码本身另由 [SecureStore] 加密）。
 * 记录格式：`ssid \t label`，多行。
 *
 * 本文件为纯 JVM 代码，可离线编译与测试。
 */
class WifiAccountMap(private val kv: KeyValueStore) {

    companion object {
        const val KEY_MAP = "wifi_account_map_v1"
    }

    /** 全部映射（SSID → label），按 SSID 排序。 */
    fun mapping(): Map<String, String> {
        val blob = kv.getString(KEY_MAP) ?: return emptyMap()
        val out = sortedMapOf<String, String>()
        blob.split("\n").filter { it.isNotEmpty() }.forEach { line ->
            val f = TextEscaping.splitFields(line)
            if (f.size >= 2 && f[0].isNotEmpty()) out[f[0]] = f[1]
        }
        return out
    }

    fun labelFor(ssid: String?): String? {
        if (ssid.isNullOrEmpty()) return null
        return mapping()[ssid]
    }

    /** 绑定（覆盖式）；空 SSID 或空 label 会被拒绝。 */
    fun bind(ssid: String, label: String) {
        require(ssid.isNotEmpty()) { "ssid 不能为空" }
        require(label.isNotEmpty()) { "label 不能为空" }
        val m = mapping().toMutableMap()
        m[ssid] = label
        save(m)
    }

    fun unbind(ssid: String): Boolean {
        val m = mapping().toMutableMap()
        val removed = m.remove(ssid) != null
        if (removed) save(m)
        return removed
    }

    /** 删除某条凭据时清理其所有绑定；返回被清理的 SSID 条数。 */
    fun unbindByLabel(label: String): Int {
        val m = mapping().toMutableMap()
        val victims = m.filterValues { it == label }.keys.toList()
        victims.forEach { m.remove(it) }
        if (victims.isNotEmpty()) save(m)
        return victims.size
    }

    fun ssidsOf(label: String): List<String> = mapping().filterValues { it == label }.keys.toList()

    fun clear() = kv.remove(KEY_MAP)

    private fun save(m: Map<String, String>) {
        if (m.isEmpty()) {
            kv.remove(KEY_MAP)
            return
        }
        kv.putString(
            KEY_MAP,
            m.entries.sortedBy { it.key }
                .joinToString("\n") { TextEscaping.joinFields(listOf(it.key, it.value)) }
        )
    }
}