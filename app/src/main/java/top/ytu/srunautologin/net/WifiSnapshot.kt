package top.ytu.srunautologin.net

/** 一条扫描结果（SSID + 信号强度 dBm）。 */
data class WifiScanEntry(val ssid: String, val level: Int)

/**
 * WiFi 数据可用性诊断（wifi-fix1 / 任务 B：让「权限已授予但系统读不到」在界面可见）。
 *
 * 为什么新增类型而不是给既有 [WifiCapability] 加字段：`WifiCapability` 是已冻结的 data class，
 * 既有调用方与离线核对程序按**旧构造函数签名**编译链接；加字段会改变 JVM 构造函数签名，
 * 老调用点会在运行时 NoSuchMethodError。新增类型 + 新增方法对既有二进制调用方是安全的。
 */
enum class WifiDataStatus {
    /** 权限不足（用户拒绝 / 未申请）→ 走既有降级路径。 */
    NO_PERMISSION,

    /** WiFi 开关关闭。 */
    WIFI_DISABLED,

    /** 权限已授予，但系统**一条 WiFi 信息都没返回**（真机最可能是系统「位置信息」总开关关闭 / 数据被遮罩）。 */
    GRANTED_NO_DATA,

    /** 权限已授予、列表有数据，但读不到「当前连接」。 */
    GRANTED_NO_CURRENT,

    /** 数据正常。 */
    OK
}

/** 一次诊断的结论：状态 + 给用户看的一句提示（正常时为 null）。 */
data class WifiDiagnosis(val status: WifiDataStatus, val hint: String?)

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

        /**
         * 「权限已授予但系统没返回数据」的统一提示。
         * 与 res/values/strings.xml 的 `ssid_list_empty_no_data` 同措辞（纯逻辑层不引用资源，故此处再声明一份）。
         */
        const val HINT_GRANTED_NO_DATA =
            "已获得权限，但系统未返回 WiFi 信息。请检查系统「位置信息」总开关是否开启（Android 12+ 起 WiFi 扫描属于位置信息）"

        /** WiFi 开关关闭时的提示。 */
        const val HINT_WIFI_DISABLED = "WiFi 开关未开启：请先打开 WiFi"

        /** 权限未授予（降级路径）时的提示。 */
        const val HINT_NO_PERMISSION = "未授予 WiFi 权限：仅检测当前连接的 WiFi，不显示周边列表"
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
            val ssid = normalize(entry.ssid, quoted = false) ?: continue
            val old = bestLevelBySsid[ssid]
            if (old == null || entry.level > old) bestLevelBySsid[ssid] = entry.level
        }
        return bestLevelBySsid.entries
            .map { it.key to it.value }
            .sortedWith(compareByDescending<Pair<String, Int>> { it.second }.thenBy { it.first })
            .map { it.first }
    }

    fun capability(): WifiCapability = WifiPermissionPolicy.capability(permission.state())

    /**
     * 诊断（任务 B）：把「权限状态 + WiFi 开关 + 实际拿到的数据」合并成一个**可见结论**。
     *
     * 关键点：`state() == GRANTED` 只说明权限位被授予，**不说明系统真的给了数据**——真机上出现过
     * 「权限显示已授权、`currentSsid()` 为 null 且列表为空」，而旧界面在这种情况完全沉默
     * （旧提示仅在 DENIED 时出现），用户无法自诊断。本方法把该状态显式化。
     */
    fun diagnose(): WifiDiagnosis {
        val state = permission.state()
        if (!WifiPermissionPolicy.canScan(state)) {
            return WifiDiagnosis(WifiDataStatus.NO_PERMISSION, HINT_NO_PERMISSION)
        }
        if (!isWifiEnabledSafely()) {
            return WifiDiagnosis(WifiDataStatus.WIFI_DISABLED, HINT_WIFI_DISABLED)
        }
        val current = currentSsid()
        val list = scanSsidList()
        return when {
            current == null && list.isEmpty() ->
                WifiDiagnosis(WifiDataStatus.GRANTED_NO_DATA, HINT_GRANTED_NO_DATA)
            current == null ->
                WifiDiagnosis(WifiDataStatus.GRANTED_NO_CURRENT, "未检测到当前连接的 WiFi（未连接，或系统未返回当前连接信息）")
            else -> WifiDiagnosis(WifiDataStatus.OK, null)
        }
    }

    /** 读 WiFi 开关；只兜「与系统交互」这一步的 SecurityException，返回「关闭」（不静默放行）。 */
    private fun isWifiEnabledSafely(): Boolean = try {
        source.isWifiEnabled()
    } catch (e: SecurityException) {
        false
    }

    /**
     * SSID 归一化（wifi-fix1 / 缺陷 R3 修复）。
     *
     * `WifiInfo.getSSID()` 的返回约定：
     *  - SSID 是合法 UTF-8 → **带双引号**（如 `"MyWiFi"`）；
     *  - 非 UTF-8 → 返回 **hex 串**（不带引号，形如 `0x414243`）；
     *  - 不可用（未连接 / 无权限）→ 返回 [UNKNOWN_SSID]（`<unknown ssid>`，也可能被引号包住）。
     * 旧实现只 trim、不去双引号 → 界面显示带引号的名字，且与 `WifiAccountMap` 的精确匹配失配。
     *
     * 规则：首尾都是 `"` 则剥掉这一对再 trim；结果为空 → null；等于 [UNKNOWN_SSID] → null
     * （带引号形态剥引号后同样命中）；非 UTF-8 的 hex 串**原样保留**（它是系统给的合法标识，不猜测解码）。
     */
    private fun normalize(raw: String?, quoted: Boolean = true): String? {
        var s = raw.orEmpty()
        if (quoted && s.length >= 2 && s.first() == '"' && s.last() == '"') {
            s = s.substring(1, s.length - 1)
        }
        if (s.isEmpty() || s == UNKNOWN_SSID) return null
        return s
    }
}