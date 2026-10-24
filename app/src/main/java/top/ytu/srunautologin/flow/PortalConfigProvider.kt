package top.ytu.srunautologin.flow

import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.PortalConfig

class StoredPortalProvider(private val store: KeyValueStore) : PortalProvider {
    override fun portal(): String = PortalConfig.read(store)
    override fun allowInsecureHttp(): Boolean = PortalConfig.allowsInsecureHttp(store)
    override fun settings(): top.ytu.srunautologin.auth.PortalConnectionSettings = PortalConfig.settings(store)
}
