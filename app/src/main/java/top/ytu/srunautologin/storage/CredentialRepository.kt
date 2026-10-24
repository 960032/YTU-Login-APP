package top.ytu.srunautologin.storage

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

    /** Missing data is empty; unreadable data is an error and must never be overwritten as empty. */
    fun list(): List<Credential> {
        synchronized(StorageTransactions.monitor) {
        val blob = kv.getString(KEY_BLOB) ?: return emptyList()
        val plain = secureStore.decryptFromBase64String(blob)
        if (plain.isEmpty()) return emptyList()
        return plain.split(RECORD_SEPARATOR)
            .filter { it.isNotEmpty() }
            .mapNotNull { line ->
                val f = TextEscaping.splitFields(line)
                if (f.size != 5) throw SecureStoreException("凭据格式损坏，已保留原有数据")
                runCatching {
                    Credential(
                        label = f[0],
                        username = f[1],
                        password = f[2],
                        carrier = f[3],
                        acId = f[4]
                    )
                }.getOrElse { throw SecureStoreException("凭据格式损坏，已保留原有数据", it) }
            }
        }
}

    fun find(label: String): Credential? = list().firstOrNull {
        synchronized(StorageTransactions.monitor) { it.label == label     }
}

    fun upsert(credential: Credential): Boolean {
        synchronized(StorageTransactions.monitor) {
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
}

    fun delete(label: String): Boolean {
        synchronized(StorageTransactions.monitor) {
        val all = list().toMutableList()
        val removed = all.removeAll { it.label == label }
        if (removed) {
            save(all)
            if (selectedLabel() == label) kv.remove(KEY_SELECTED)
        }
        return removed
        }
}

    fun clear() {
        synchronized(StorageTransactions.monitor) {
        kv.remove(KEY_BLOB)
        kv.remove(KEY_SELECTED)
        }
}

    fun selectedLabel(): String? = kv.getString(KEY_SELECTED)

    fun select(label: String): Boolean {
        synchronized(StorageTransactions.monitor) {
        if (find(label) == null) return false
        kv.putString(KEY_SELECTED, label)
        return true
        }
}

    fun selected(): Credential? = selectedLabel()?.let { find(it) }

    fun selectedSummary(): String? = selected()?.let { "${it.label}（${Carrier.displayName(it.carrier)}）" }

    private fun save(all: List<Credential>) {
        val plain = all.joinToString(RECORD_SEPARATOR) { c ->
            TextEscaping.joinFields(listOf(c.label, c.username, c.password, c.carrier, c.acId))
        }
        kv.putString(KEY_BLOB, secureStore.encryptToBase64String(plain))
    }

    fun persistedBlob(): String? = kv.getString(KEY_BLOB)

    fun persistedBlobBytes(): ByteArray? =
        persistedBlob()?.let { SecureStore.base64ToBytes(it) }
}