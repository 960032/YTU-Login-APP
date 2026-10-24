package top.ytu.srunautologin.storage

import java.net.URI
import top.ytu.srunautologin.auth.PortalEndpoint
import top.ytu.srunautologin.auth.PortalConnectionSettings

/** Portal transport policy and origin-scoped consent for legacy HTTP portals. */
object PortalConfig {
    const val KEY_PORTAL = "srun_portal_v1"
    const val KEY_INSECURE_ORIGIN = "srun_insecure_portal_origin_v1"
    const val DEFAULT_PORTAL = "https://202.194.116.116"

    fun normalize(raw: String): String? = PortalEndpoint.normalize(raw)

    fun read(store: KeyValueStore?): String {
        val raw = store?.getString(KEY_PORTAL) ?: return DEFAULT_PORTAL
        // Old versions saved only a host and always used HTTP. Preserve that origin,
        // without inventing consent for sending the saved credentials without TLS.
        return PortalEndpoint.normalize(raw, defaultScheme = "http").orEmpty()
    }

    fun readHost(store: KeyValueStore?): String? = try { URI(read(store)).host }
    catch (_: Exception) { null }

    fun allowsInsecureHttp(store: KeyValueStore?, origin: String = read(store)): Boolean =
        PortalEndpoint.isCleartext(origin) && store?.getString(KEY_INSECURE_ORIGIN) == origin

    fun settings(store: KeyValueStore?): PortalConnectionSettings = StorageTransactions.withLock {
        val origin = read(store)
        PortalConnectionSettings(origin, allowsInsecureHttp(store, origin))
    }

    fun write(store: KeyValueStore, raw: String, allowInsecureHttp: Boolean = false): String? = StorageTransactions.withLock {
        val origin = normalize(raw) ?: return@withLock null
        // Revoke old consent before changing the destination; failures stay fail-closed.
        store.remove(KEY_INSECURE_ORIGIN)
        store.putString(KEY_PORTAL, origin)
        if (allowInsecureHttp && PortalEndpoint.isCleartext(origin)) {
            store.putString(KEY_INSECURE_ORIGIN, origin)
        }
        origin
    }
}
