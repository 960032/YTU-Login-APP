package top.ytu.srunautologin.storage

import top.ytu.srunautologin.flow.EnabledAccountLookup
import top.ytu.srunautologin.flow.WifiAccountLookup
import java.util.logging.Logger

data class SavedAccount(
    val label: String,
    val username: String,
    val password: String,
    val ssid: String = "",
    val enabled: Boolean = true
) {
    init {
        require(label.isNotBlank()) { "label 不能为空" }
    }

    override fun toString(): String =
        "SavedAccount(label=$label, username=${top.ytu.srunautologin.log.AccountMask.maskAccount(username)}, password=***, ssid=$ssid, enabled=$enabled)"
}

class AccountStore(
    private val secureStore: SecureStore,
    private val kv: KeyValueStore,
    private val legacyMap: WifiAccountMap = WifiAccountMap(kv)
) : WifiAccountLookup, EnabledAccountLookup {

    companion object {
        private val LOG = Logger.getLogger("SrunAutoLogin")

        const val KEY_ACCOUNTS = "accounts_v2"

        const val KEY_MIGRATED = "accounts_v2_migrated"

        const val FIELD_SEPARATOR = "\t"
        const val RECORD_SEPARATOR = "\n"

        const val FIELD_COUNT = 5
    }

    fun list(): List<SavedAccount> {
        synchronized(StorageTransactions.monitor) {
        migrateIfNeeded()
        return readV2()
        }
}

    fun enabled(): List<SavedAccount> = list().filter { it.enabled }

    fun find(ssid: String?): SavedAccount? {
        if (ssid.isNullOrEmpty()) return null
        return list().firstOrNull { it.ssid == ssid }
    }

    fun findByName(label: String): SavedAccount? = list().firstOrNull { it.label == label }

    fun enabledFor(ssid: String?): SavedAccount? {
        if (ssid.isNullOrEmpty()) return null
        return list().firstOrNull { it.ssid == ssid && it.enabled }
    }

    override fun hasEnabledAccountFor(ssid: String?): Boolean = enabledFor(ssid) != null
    override val providesCredentials: Boolean get() = true
    override fun credentialForSsid(ssid: String): Credential? = enabledFor(ssid)?.let(::toCredential)

    override fun labelFor(ssid: String?): String? = enabledFor(ssid)?.label

    fun credentialFor(label: String): Credential? = findByName(label)?.let { toCredential(it) }

    fun selectedCredential(): Credential? =
        selectedLabel()?.let { findByName(it) }?.let { toCredential(it) }

    fun selectedLabel(): String? = kv.getString(CredentialRepository.KEY_SELECTED)

    fun summary(account: SavedAccount): String =
        "${account.label} ↔ ${account.ssid.ifBlank { "未绑定网络" }}"

    private fun toCredential(a: SavedAccount): Credential =
        Credential(
            label = a.label,
            username = a.username,
            password = a.password,
            carrier = Carrier.YTU,      // v2 未保存登录方式：既有口径下 carrier 只影响显示，不参与认证
            acId = Carrier.AC_ID        // 已冻结：字符串 "5"
        )

    fun save(
        ssid: String,
        label: String,
        username: String,
        password: String,
        enabled: Boolean? = null
    ): Boolean {
        synchronized(StorageTransactions.monitor) {
        val all = list().toMutableList()
        val idx = all.indexOfFirst { it.ssid == ssid && ssid.isNotEmpty() }
        val isNew = idx < 0
        val next = if (isNew) {
            SavedAccount(
                label = label,
                username = username,
                password = password,
                ssid = ssid,
                enabled = enabled ?: true          // 新增默认勾选（参与早上匹配）
            )
        } else {
            val old = all[idx]
            old.copy(
                label = label,
                username = username,
                password = password,
                enabled = enabled ?: old.enabled
            )
        }
        if (isNew) all.add(next) else all[idx] = next
        writeV2(all)
        mirrorToV1(next)
        return isNew
        }
}

    fun update(
        ssid: String,
        label: String? = null,
        username: String? = null,
        password: String? = null,
        enabled: Boolean? = null,
        newSsid: String? = null
    ): Boolean {
        synchronized(StorageTransactions.monitor) {
        val all = list().toMutableList()
        val idx = all.indexOfFirst { it.ssid == ssid && ssid.isNotEmpty() }
        if (idx < 0) {
            save(
                ssid = newSsid ?: ssid,
                label = label ?: "",
                username = username ?: "",
                password = password ?: "",
                enabled = enabled
            )
            return true
        }
        val old = all[idx]
        val destination = newSsid ?: old.ssid
        require(all.withIndex().none { it.index != idx && it.value.ssid == destination }) { "目标 WiFi 已绑定其他账号" }
        all[idx] = old.copy(
            label = label ?: old.label,
            username = username ?: old.username,
            password = password ?: old.password,
            ssid = newSsid ?: old.ssid,
            enabled = enabled ?: old.enabled
        )
        writeV2(all)
        if (old.ssid != all[idx].ssid) unbindLegacy(old.ssid)
        mirrorToV1(all[idx])
        clearSelectionIfDangling(setOf(old.label))
        return false
        }
}

    fun delete(ssid: String, label: String? = null): Boolean {
        synchronized(StorageTransactions.monitor) {
        val all = list().toMutableList()
        val victims = all.filter { it.ssid == ssid && (ssid.isNotEmpty() || (label != null && it.label == label)) }
        if (victims.isEmpty()) return false
        victims.forEach { all.remove(it) }
        writeV2(all)
        unbindLegacy(ssid)
        clearSelectionIfDangling(victims.map { it.label }.toSet())
        return true
        }
}

    fun deleteByLabel(label: String): Boolean {
        synchronized(StorageTransactions.monitor) {
        val all = list().toMutableList()
        val victims = all.filter { it.label == label }
        if (victims.isEmpty()) return false
        victims.forEach { all.remove(it) }
        writeV2(all)
        victims.map { it.ssid }.filter { it.isNotEmpty() }.forEach { unbindLegacy(it) }
        clearSelectionIfDangling(setOf(label))
        return true
        }
}

    fun setEnabled(ssid: String, enabled: Boolean): Boolean {
        synchronized(StorageTransactions.monitor) {
        if (find(ssid) == null) return false
        update(ssid = ssid, enabled = enabled)
        return true
        }
}

    private fun unbindLegacy(ssid: String) {
        runCatching { legacyMap.unbind(ssid) }.onFailure {
            LOG.warning("删除账号时清理 WiFi 绑定失败（已忽略）：${it.javaClass.simpleName}: ${it.message}")
        }
    }

    private fun clearSelectionIfDangling(deletedLabels: Set<String>) {
        val remaining = readV2()
        val dangling = deletedLabels.filter { lbl -> remaining.none { it.label == lbl } }
        if (dangling.isEmpty()) return
        dangling.forEach { CredentialRepository(secureStore, kv).delete(it) }
        val selected = selectedLabel() ?: return
        if (selected in dangling) kv.remove(CredentialRepository.KEY_SELECTED)
    }

    fun clear() {
        synchronized(StorageTransactions.monitor) {
        writeV2(emptyList())
        }
}

    private fun migrateIfNeeded() {
        if (!kv.getString(KEY_ACCOUNTS).isNullOrEmpty()) return     // ① v2 已有数据
        if (kv.getString(KEY_MIGRATED) == "1") return               // ② 迁移已做过（含「之后被删空」）
        val legacyBlob = kv.getString(CredentialRepository.KEY_BLOB) ?: return  // ③ 没有 v1 数据，无需迁移

        val migrated = migrateFromLegacyV1(legacyBlob)
        if (migrated.isEmpty()) return    // v1 解不开时不置位，等密钥恢复后还有机会迁移
        writeV2(migrated)
        kv.putString(KEY_MIGRATED, "1")
        LOG.info("已把 v1 账号存储迁移到 accounts_v2：共 ${migrated.size} 条")
    }

    private fun migrateFromLegacyV1(legacyBlob: String): List<SavedAccount> {
        val plain = secureStore.decryptFromBase64String(legacyBlob)
        if (plain.isEmpty()) return emptyList()
        val mapping = runCatching { legacyMap.mapping() }.getOrElse { emptyMap() }
        return plain.split(CredentialRepository.RECORD_SEPARATOR)
            .filter { it.isNotEmpty() }
            .mapIndexed { index, line ->
                val f = TextEscaping.splitFields(line)
                if (f.size < 5) throw SecureStoreException("旧凭据格式损坏，已保留原有数据")
                val label = f[0].takeIf { it.isNotBlank() }
                    ?: f[1].takeIf { it.isNotBlank() }
                    ?: "账号${index + 1}"
                val ssids = mapping.filterValues { it == label }.keys.sorted().ifEmpty { listOf("") }
                ssids.map { ssid -> SavedAccount(label, f[1], f[2], ssid, true) }
            }.flatten()
    }

    private fun legacySsidFor(label: String, mapping: Map<String, String>): String =
        mapping.entries.filter { it.value == label }.map { it.key }.minOrNull() ?: ""

    private fun readV2(): List<SavedAccount> {
        val blob = kv.getString(KEY_ACCOUNTS) ?: return emptyList()
        if (blob.isEmpty()) return emptyList()
        val plain = secureStore.decryptFromBase64String(blob)
        if (plain.isEmpty()) return emptyList()
        val parsed = plain.split(RECORD_SEPARATOR)
            .filter { it.isNotEmpty() }
            .mapNotNull { line ->
                val f = TextEscaping.splitFields(line)
                if (f.size != FIELD_COUNT || f[4] !in setOf("0", "1")) throw SecureStoreException("账号格式损坏，已保留原有数据")
                val label = f[0]
                if (label.isBlank()) throw SecureStoreException("账号备注损坏，已保留原有数据")
                SavedAccount(
                    label = label,
                    username = f[1],
                    password = f[2],
                    ssid = f[3],
                    enabled = f[4] != "0"     // 容错：只有明确的 "0" 才算未勾选
                )
            }
        return parsed.sortedWith(compareBy({ it.ssid }, { it.label }))
    }

    private fun writeV2(all: List<SavedAccount>) {
        if (all.isEmpty()) {
            kv.putAll(mapOf(KEY_MIGRATED to "1", KEY_ACCOUNTS to null))
            return
        }
        val plain = all.joinToString(RECORD_SEPARATOR) { a ->
            TextEscaping.joinFields(
                listOf(a.label, a.username, a.password, a.ssid, if (a.enabled) "1" else "0")
            )
        }
        val blob = secureStore.encryptToBase64String(plain)
        kv.putAll(mapOf(KEY_ACCOUNTS to blob, KEY_MIGRATED to "1"))
    }

    private fun mirrorToV1(account: SavedAccount) {
        try {
            val repo = CredentialRepository(secureStore, kv)
            repo.upsert(
                Credential(
                    label = account.label,
                    username = account.username,
                    password = account.password,
                    carrier = Carrier.YTU,
                    acId = Carrier.AC_ID
                )
            )
            repo.select(account.label)
            if (account.ssid.isNotEmpty()) legacyMap.bind(account.ssid, account.label)
        } catch (e: Throwable) {
            LOG.warning("v1 镜像写入失败（已忽略，v2 已保存）：${e.javaClass.simpleName}")
        }
    }

    fun persistedBlob(): String? = kv.getString(KEY_ACCOUNTS)

    fun migrationDone(): Boolean = kv.getString(KEY_MIGRATED) == "1"
}
