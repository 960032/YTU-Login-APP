package top.ytu.srunautologin.net

/** 一条扫描结果（SSID + 信号强度 dBm）。 */
data class WifiScanEntry(val ssid: String, val level: Int)

/**
 * WiFi 原始数据源接口：把 Android WifiManager 挡在接口后面，
 * 使快照逻辑（去重/排序/降级）可在纯 JVM 测试。
 *
 * 真机实现：top.ytu.srunautologin.platform.AndroidWifiSource。
 * 实现约定：无权限/系统抛 SecurityException 时返回 null / 空列表，不向调用方抛异常。
 */
interface WifiSource {
    fun isWifiEnabled(): Boolean

    /** 当前连接的 WiFi SSID；未连接、未启用或无权限时返回 null。 */
    fun currentSsidRaw(): String?

    /** 系统检测到的 WiFi 列表（未去重、未排序，可含重复 SSID 与空 SSID）。 */
    fun scanSsidEntries(): List<WifiScanEntry>
}

/**
 * WiFi 快照核心逻辑（纯 JVM）：
 *  - [currentSsid]  ：当前连接的 SSID；未连 WiFi / 权限不足返回 null；
 *  - [scanSsidList] ：系统检测到的 SSID 列表，去重 + 按信号强度降序；
 *  - [capability]   ：按当前权限给出能力与降级原因。
 *
 * 降级规则（用户要求）：权限 DENIED 时**不扫描列表**（返回空列表），但仍尝试读当前 SSID。
 */
class WifiSnapshotCore(
    private val source: WifiSource,
    private val permission: WifiPermissionFlow
) {
    companion object {
        /** Android 在 SSID 不可见时返回的占位串。 */
        const val UNKNOWN_SSID = "<unknown ssid>"
    }

    fun currentSsid(): String? {
        if (!WifiPermissionPolicy.canReadCurrentSsid(permission.state())) return null
        return try {
            if (!source.isWifiEnabled()) return null
            normalize(source.currentSsidRaw())
        } catch (e: SecurityException) {
            // 权限被撤销/系统拒绝：降级为「读不到」，不向 UI 抛异常
            null
        }
    }

    fun scanSsidList(): List<String> {
        if (!WifiPermissionPolicy.canScan(permission.state())) return emptyList()
        val entries = try {
            source.scanSsidEntries()
        } catch (e: SecurityException) {
            return emptyList()
        }
        val bestLevelBySsid = LinkedHashMap<String, Int>()
        for (entry in entries) {
            val ssid = normalize(entry.ssid) ?: continue
            val old = bestLevelBySsid[ssid]
            if (old == null || entry.level > old) bestLevelBySsid[ssid] = entry.level
        }
        return bestLevelBySsid.entries
            .map { it.key to it.value }
            .sortedWith(compareByDescending<Pair<String, Int>> { it.second }.thenBy { it.first })
            .map { it.first }
    }

    fun capability(): WifiCapability = WifiPermissionPolicy.capability(permission.state())

    private fun normalize(raw: String?): String? {
        val s = raw?.trim().orEmpty()
        if (s.isEmpty() || s == UNKNOWN_SSID) return null
        return s
    }
}