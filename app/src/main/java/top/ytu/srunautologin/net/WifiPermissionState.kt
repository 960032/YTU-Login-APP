package top.ytu.srunautologin.net

/**
 * WiFi 能力所依赖的权限状态。
 *
 * - GRANTED      ：所需权限已授予，可读当前 SSID + 扫描列表；
 * - DENIED       ：用户拒绝授权 → **降级**：只检测当前连接的 WiFi，不扫描列表；
 * - NOT_REQUIRED ：当前系统版本不需要该运行时权限（API 26，Android 8.1 之前读 SSID 不需要位置权限）。
 */
enum class WifiPermissionState { GRANTED, DENIED, NOT_REQUIRED }

/** 权限申请结果（UI 弹窗返回后回调）。 */
enum class WifiPermissionRequestOutcome { GRANTED, DENIED }

/** 按当前权限能做什么（降级规则的对外表达）。 */
data class WifiCapability(
    val canReadCurrentSsid: Boolean,
    val canScanList: Boolean,
    /** 降级原因（供 UI 提示用户），未降级时为 null。 */
    val degradedReason: String?
) {
    val degraded: Boolean get() = degradedReason != null
}

/**
 * 系统版本 → 所需权限的规则表（覆盖 minSdk 26 → targetSdk 36）。
 *
 * 依据：
 *  - Android 8.1（API 27）起，读取 SSID / 获取扫描结果需要 ACCESS_FINE_LOCATION（API 26 不需要）；
 *  - Android 13（API 33）起，读取 SSID / 扫描改用 NEARBY_WIFI_DEVICES；
 *    为兼容仍申请了精确位置的应用，API 33+ 时 FINE_LOCATION 也视为等效授权；
 *  - ACCESS_WIFI_STATE / CHANGE_WIFI_STATE 是普通权限（安装即授予，无运行时弹窗），不参与本状态机。
 *
 * 权限名字符串与 android.Manifest.permission 中的常量值逐字相同（本文件不引用 Android API，
 * 以保证逻辑可在纯 JVM 环境中测试）。
 */
object WifiPermissionPolicy {
    const val ACCESS_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
    const val ACCESS_COARSE_LOCATION = "android.permission.ACCESS_COARSE_LOCATION"
    const val NEARBY_WIFI_DEVICES = "android.permission.NEARBY_WIFI_DEVICES"
    const val ACCESS_WIFI_STATE = "android.permission.ACCESS_WIFI_STATE"
    const val CHANGE_WIFI_STATE = "android.permission.CHANGE_WIFI_STATE"

    /** Android 8.1：读 SSID / 扫描开始需要位置权限。 */
    const val API_SSID_LOCKDOWN = 27

    /** Android 13：改用 NEARBY_WIFI_DEVICES。 */
    const val API_NEARBY_WIFI = 33

    /** 最低支持版本（与 app/build.gradle.kts 的 minSdk 26 一致）。 */
    const val MIN_SDK = 26
    const val MAX_SDK = 36

    /** 该 API 等级下，读取 SSID 与扫描列表所需的**运行时**权限；空集表示无需运行时权限。 */
    fun requiredPermissions(sdkInt: Int): List<String> = when {
        sdkInt < API_SSID_LOCKDOWN -> emptyList()
        sdkInt < API_NEARBY_WIFI -> listOf(ACCESS_FINE_LOCATION)
        else -> listOf(NEARBY_WIFI_DEVICES)
    }

    /** 由「系统版本 + 已授予权限集合」推导 [WifiPermissionState]。 */
    fun state(sdkInt: Int, grantedPermissions: Set<String>): WifiPermissionState {
        val required = requiredPermissions(sdkInt)
        if (required.isEmpty()) return WifiPermissionState.NOT_REQUIRED
        val satisfied = required.any { it in grantedPermissions } ||
            (sdkInt >= API_NEARBY_WIFI && ACCESS_FINE_LOCATION in grantedPermissions)
        return if (satisfied) WifiPermissionState.GRANTED else WifiPermissionState.DENIED
    }

    /** 降级规则：DENIED 时不扫描列表；其余状态可扫描。 */
    fun canScan(state: WifiPermissionState): Boolean = state != WifiPermissionState.DENIED

    /** 降级规则：无论权限如何，都**尝试**读取当前连接的 SSID（拒绝时可能拿到 null）。 */
    fun canReadCurrentSsid(state: WifiPermissionState): Boolean = true

    /** 由权限状态生成能力描述（含降级原因文案）。 */
    fun capability(state: WifiPermissionState): WifiCapability = when (state) {
        WifiPermissionState.GRANTED, WifiPermissionState.NOT_REQUIRED ->
            WifiCapability(canReadCurrentSsid = true, canScanList = true, degradedReason = null)
        WifiPermissionState.DENIED ->
            WifiCapability(
                canReadCurrentSsid = true,
                canScanList = false,
                degradedReason = "未授予 WiFi 权限：仅检测当前连接的 WiFi，不扫描附近列表；" +
                    "可在系统设置中授权后恢复完整功能"
            )
    }
}

/**
 * 权限申请流程接口。需求原文：「先说明权限用途，然后申请权限，若不同意则只检查当前 wifi」。
 *
 * 顺序被接口固化：UI 必须先调用 [markRationaleShown]（已向用户说明用途），
 * 之后才允许把系统弹窗结果交给 [onRequestResult]；顺序颠倒会抛异常。
 * 本任务不实现弹窗（由后续 UI 任务实现），只提供该顺序能力与结果 → 能力的映射。
 */
interface WifiPermissionFlow {
    /** 说明用途的文案（UI 在申请前展示）。 */
    val explainText: String

    fun requiredPermissions(): List<String>

    /** 当前权限状态（只读查询，任何时候可调用）。 */
    fun state(): WifiPermissionState

    fun isRationaleShown(): Boolean

    /** 第 1 步：UI 已向用户说明用途。 */
    fun markRationaleShown()

    /** 第 2 步：系统弹窗返回结果 → 更新能力状态。必须先调用 [markRationaleShown]。 */
    fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState
}

/**
 * [WifiPermissionFlow] 的默认实现（纯逻辑，可在 JVM 测试）。
 *
 * @param sdkInt            Build.VERSION.SDK_INT
 * @param initiallyGranted  当前已授予的权限集合（真机由 Context.checkSelfPermission 收集）
 */
class DefaultWifiPermissionFlow(
    private val sdkInt: Int,
    initiallyGranted: Set<String> = emptySet()
) : WifiPermissionFlow {

    private val granted: MutableSet<String> = initiallyGranted.toMutableSet()
    private var rationaleShown = false

    override val explainText: String =
        "本应用需要「附近设备（WiFi）」权限，用于读取当前连接的 WiFi 名称与可用 WiFi 列表，" +
            "以便按您设置的 WiFi-账号对应关系自动登录。该信息仅在本机使用，不会上传。"

    override fun requiredPermissions(): List<String> = WifiPermissionPolicy.requiredPermissions(sdkInt)

    override fun state(): WifiPermissionState = WifiPermissionPolicy.state(sdkInt, granted)

    override fun isRationaleShown(): Boolean = rationaleShown

    override fun markRationaleShown() {
        rationaleShown = true
    }

    override fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState {
        check(rationaleShown) {
            "顺序错误：必须先调用 markRationaleShown() 向用户说明权限用途，才能处理申请结果"
        }
        val required = requiredPermissions()
        if (outcome == WifiPermissionRequestOutcome.GRANTED) {
            granted.addAll(required)
        } else {
            required.forEach { granted.remove(it) }
        }
        return state()
    }

    /** 真机用：系统设置里被手动改动后重新同步已授予权限。 */
    fun syncGrantedPermissions(permissions: Set<String>) {
        granted.clear()
        granted.addAll(permissions)
    }
}