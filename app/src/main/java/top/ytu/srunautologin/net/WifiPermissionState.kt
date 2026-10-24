package top.ytu.srunautologin.net

enum class WifiPermissionState { GRANTED, DENIED, NOT_REQUIRED }

enum class WifiPermissionRequestOutcome { GRANTED, DENIED }

data class WifiCapability(
    val canReadCurrentSsid: Boolean,
    val canScanList: Boolean,
    val degradedReason: String?
) {
    val degraded: Boolean get() = degradedReason != null
}

object WifiPermissionPolicy {
    const val ACCESS_FINE_LOCATION = "android.permission.ACCESS_FINE_LOCATION"
    const val ACCESS_COARSE_LOCATION = "android.permission.ACCESS_COARSE_LOCATION"
    const val NEARBY_WIFI_DEVICES = "android.permission.NEARBY_WIFI_DEVICES"
    const val ACCESS_WIFI_STATE = "android.permission.ACCESS_WIFI_STATE"
    const val CHANGE_WIFI_STATE = "android.permission.CHANGE_WIFI_STATE"

    const val API_SSID_LOCKDOWN = 27

    const val API_NEARBY_WIFI = 33

    const val MIN_SDK = 26
    const val MAX_SDK = 36

    fun requiredPermissions(sdkInt: Int): List<String> = when {
        sdkInt < API_SSID_LOCKDOWN -> emptyList()
        sdkInt < API_NEARBY_WIFI -> listOf("android.permission.ACCESS_COARSE_LOCATION", ACCESS_FINE_LOCATION)
        else -> listOf(NEARBY_WIFI_DEVICES, "android.permission.ACCESS_COARSE_LOCATION", ACCESS_FINE_LOCATION)
    }

    fun state(sdkInt: Int, grantedPermissions: Set<String>): WifiPermissionState {
        val required = requiredPermissions(sdkInt)
        if (required.isEmpty()) return WifiPermissionState.NOT_REQUIRED
        val satisfied = ACCESS_FINE_LOCATION in grantedPermissions
        return if (satisfied) WifiPermissionState.GRANTED else WifiPermissionState.DENIED
    }

    fun canScan(state: WifiPermissionState): Boolean = state != WifiPermissionState.DENIED

    fun canReadCurrentSsid(state: WifiPermissionState): Boolean = true

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

interface WifiPermissionFlow {
    val explainText: String

    fun requiredPermissions(): List<String>

    fun state(): WifiPermissionState

    fun isRationaleShown(): Boolean

    fun markRationaleShown()

    fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState
}

class DefaultWifiPermissionFlow(
    private val sdkInt: Int,
    initiallyGranted: Set<String> = emptySet()
) : WifiPermissionFlow {

    private val granted: MutableSet<String> = initiallyGranted.toMutableSet()
    private var rationaleShown = false

    override val explainText: String =
        "读取 WiFi 信息需要「位置信息」权限（Android 规定 WiFi 名称与列表属于位置信息）。请授予「精确位置」，" +
            "以便读取当前连接的 WiFi 名称与可用 WiFi 列表，按您设置的 WiFi-账号对应关系自动登录。" +
            "该信息仅在本机使用，不会上传。"

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

    fun syncGrantedPermissions(permissions: Set<String>) {
        granted.clear()
        granted.addAll(permissions)
    }
}