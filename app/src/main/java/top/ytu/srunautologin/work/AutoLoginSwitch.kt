package top.ytu.srunautologin.work

import top.ytu.srunautologin.storage.KeyValueStore

object AutoLoginSwitch {
    const val KEY_ENABLED = "srun_auto_login_enabled_v1"
    const val DEFAULT_ENABLED = true
    fun encode(enabled: Boolean): String = if (enabled) "1" else "0"
    fun isDefault(store: KeyValueStore): Boolean = store.getString(KEY_ENABLED) == null
    fun isEnabled(store: KeyValueStore): Boolean = try {
        when (store.getString(KEY_ENABLED)?.lowercase()) {
            null -> DEFAULT_ENABLED
            "1", "true" -> true
            else -> false
        }
    } catch (_: RuntimeException) { false }
    fun gateReason(store: KeyValueStore, entry: String): String? =
        if (isEnabled(store)) null else "自动登录已停用，跳过：$entry"
    fun setEnabled(store: KeyValueStore, enabled: Boolean): Boolean {
        store.putString(KEY_ENABLED, encode(enabled))
        check(isEnabled(store) == enabled) { "自动登录开关未能保存" }
        return enabled
    }
}
