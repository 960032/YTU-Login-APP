package top.ytu.srunautologin.ui

import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.AuthSkip
import top.ytu.srunautologin.net.WifiCapability
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.storage.Carrier
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.PortalConfig

enum class CarrierOption(val value: String, val displayName: String) {
    YTU(Carrier.YTU, "烟台大学"),
    CMCC(Carrier.CMCC, "中国移动");

    override fun toString(): String = displayName

    companion object {
        fun fromValue(value: String): CarrierOption =
            entries.firstOrNull { it.value == value } ?: YTU

        fun displayNames(): List<String> = entries.map { it.displayName }
    }
}

data class SavePlan(
    val credential: Credential,
    val targetSsid: String,
    val label: String
)

sealed interface SaveOutcome {
    data class Saved(val plan: SavePlan) : SaveOutcome
    data class Invalid(val message: String) : SaveOutcome
}

sealed interface PortalSaveOutcome {
    data class Saved(val portal: String) : PortalSaveOutcome

    data class Invalid(val message: String) : PortalSaveOutcome
}

object InputRules {
    fun normalizeUsername(raw: String): String = raw.trim()

    fun applyCarrierDomain(username: String, carrier: CarrierOption): String {
        val u = username.trim()
        if (u.isEmpty() || u.contains('@')) return u
        return "$u@${carrier.value}"
    }

    fun labelOrDefault(raw: String, carrier: CarrierOption): String {
        val l = raw.trim()
        return if (l.isEmpty()) carrier.displayName else l
    }
}

data class ConfigUiState(
    val usernameInput: String = "",
    val passwordInput: String = "",
    val carrierIndex: Int = 0,
    val labelInput: String = CarrierOption.YTU.displayName,
    val labelTouched: Boolean = false,
    val ssidList: List<String> = emptyList(),
    val selectedSsid: String? = null,
    val currentSsid: String? = null,
    val permissionState: WifiPermissionState = WifiPermissionState.DENIED,
    val capability: WifiCapability = WifiCapability(true, false, "尚未申请 WiFi 权限"),
    val rationaleText: String = "",
    val rationaleShown: Boolean = false,
    val permissionRequested: Boolean = false,
    val noticeText: String = "",
    val statusText: String = "尚未登录",
    val statusOk: Boolean = false,
    val lastResult: AuthResult? = null,
    val lastAttemptAtMillis: Long = 0L,
    val portalInput: String = PortalConfig.DEFAULT_PORTAL,
    val busy: Boolean = false,
    val allowInsecureHttp: Boolean = false
) {
    val carrier: CarrierOption get() = CarrierOption.entries[carrierIndex.coerceIn(0, CarrierOption.entries.size - 1)]

    val degraded: Boolean get() = capability.degraded

    fun effectiveLabel(): String = InputRules.labelOrDefault(labelInput, carrier)

    fun effectiveUsername(): String = InputRules.applyCarrierDomain(usernameInput, carrier)
}

interface WifiUiPort {
    val explainText: String
    fun requiredPermissions(): List<String>
    fun permissionState(): WifiPermissionState
    fun capability(): WifiCapability
    fun markRationaleShown()
    fun onRequestResult(granted: Boolean): WifiPermissionState
    fun currentSsid(): String?
    fun scanSsidList(): List<String>
}

interface LoginTrigger {
    fun login(targetSsid: String?): AuthFlowOutcome

    companion object {
        val NOOP: LoginTrigger = object : LoginTrigger {
            override fun login(targetSsid: String?): AuthFlowOutcome =
                AuthFlowOutcome.Skipped(top.ytu.srunautologin.flow.AuthSkipReason.NO_CURRENT_SSID, null, targetSsid)
        }
    }
}

class ConfigViewModel(
    private val wifi: WifiUiPort,
    private val loginTrigger: LoginTrigger = LoginTrigger.NOOP,
    private val portalStore: KeyValueStore? = null,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {

    @Volatile
    var state: ConfigUiState = ConfigUiState(
        labelInput = CarrierOption.YTU.displayName,
        permissionState = wifi.permissionState(),
        capability = wifi.capability(),
        rationaleText = wifi.explainText,
        portalInput = portalInitialInput(portalStore),
        allowInsecureHttp = PortalConfig.allowsInsecureHttp(portalStore)
    )
        private set

    private var rationaleMarked = false

    fun setUsername(value: String): ConfigUiState = update { it.copy(usernameInput = value) }

    fun setPassword(value: String): ConfigUiState = update { it.copy(passwordInput = value) }

    fun setLabel(value: String): ConfigUiState = update { it.copy(labelInput = value, labelTouched = true) }

    fun setPortal(value: String): ConfigUiState = update {
        it.copy(portalInput = value, allowInsecureHttp = it.allowInsecureHttp &&
            PortalConfig.normalize(value) == PortalConfig.normalize(it.portalInput))
    }

    fun setAllowInsecureHttp(allow: Boolean): ConfigUiState = update {
        it.copy(allowInsecureHttp = allow && PortalConfig.normalize(it.portalInput)?.startsWith("http://") == true)
    }

    fun savePortal(): PortalSaveOutcome {
        val raw = state.portalInput
        val invalid = validatePortalInput(raw)
        if (invalid != null) {
            update { it.copy(statusText = invalid, statusOk = false) }
            return PortalSaveOutcome.Invalid(invalid)
        }
        if (PortalConfig.normalize(raw)?.startsWith("http://") == true && !state.allowInsecureHttp) {
            val message = "此门户使用 HTTP，请确认下方的未加密连接风险，或改用 HTTPS"
            update { it.copy(statusText = message, statusOk = false) }
            return PortalSaveOutcome.Invalid(message)
        }
        val store = portalStore
            ?: run {
                val msg = "保存失败：门户地址存储不可用（未注入 KeyValueStore）"
                update { it.copy(statusText = msg, statusOk = false) }
                return PortalSaveOutcome.Invalid(msg)
            }
        val saved = try { PortalConfig.write(store, raw, state.allowInsecureHttp) }
        catch (_: Exception) {
            val message = "门户设置未能保存，请重试"
            update { it.copy(statusText = message, statusOk = false) }
            return PortalSaveOutcome.Invalid(message)
        }
            ?: run {
                val msg = "保存失败：门户地址无效"
                update { it.copy(statusText = msg, statusOk = false) }
                return PortalSaveOutcome.Invalid(msg)
            }
        update {
            it.copy(
                portalInput = saved,
                statusText = "已保存门户地址：$saved（重启应用后仍然生效）",
                statusOk = true
            )
        }
        return PortalSaveOutcome.Saved(saved)
    }

    fun selectCarrier(index: Int): ConfigUiState = update { s ->
        val newCarrier = CarrierOption.entries[index.coerceIn(0, CarrierOption.entries.size - 1)]
        val autoLabel = !s.labelTouched || s.labelInput == s.carrier.displayName
        s.copy(
            carrierIndex = CarrierOption.entries.indexOf(newCarrier),
            labelInput = if (autoLabel) newCarrier.displayName else s.labelInput
        )
    }

    private fun wifiDataNotice(cap: WifiCapability, noDataAtAll: Boolean): String = when {
        !cap.canScanList -> degradeNotice(cap)
        noDataAtAll ->
            "已获得权限，但系统未返回 WiFi 信息：请先确认系统「位置信息」总开关已开启，并确认本应用已开启「精确位置」（Android 12+ 起 WiFi 名称与列表属于位置信息，关闭精确位置会读不到）"
        else -> degradeNotice(cap)
    }

    fun refreshSsidList(): ConfigUiState = update { s ->
        val list = wifi.scanSsidList()
        val current = wifi.currentSsid()
        val cap = wifi.capability()
        val selected = s.selectedSsid?.takeIf { list.contains(it) }
        s.copy(
            ssidList = list,
            selectedSsid = selected,
            currentSsid = current,
            capability = cap,
            permissionState = wifi.permissionState(),
            noticeText = wifiDataNotice(cap, current == null && list.isEmpty())
        )
    }

    fun useCurrentSsid(): ConfigUiState = update { s ->
        val current = wifi.currentSsid()
        val cap = wifi.capability()
        s.copy(
            currentSsid = current,
            selectedSsid = current ?: s.selectedSsid,
            noticeText = when {
                current != null -> "已选择当前连接的 WiFi：$current"
                !cap.canScanList -> "未检测到当前连接的 WiFi：未授予「位置信息」权限，读不到 WiFi 信息（可点上方按钮申请）"
                else -> wifiDataNotice(cap, true)
            },
            capability = cap
        )
    }

    fun selectSsid(ssid: String): ConfigUiState = update { it.copy(selectedSsid = ssid) }

    fun permissionExplanation(): String = wifi.explainText

    fun beginPermissionRequest(): ConfigUiState {
        val text = wifi.explainText
        wifi.markRationaleShown()
        rationaleMarked = true
        return update {
            it.copy(
                rationaleText = text,
                rationaleShown = true,
                permissionRequested = true,
                noticeText = "已说明权限用途，正在申请系统权限…"
            )
        }
    }

    fun onPermissionResult(granted: Boolean): ConfigUiState {
        if (!rationaleMarked) {
            return update {
                it.copy(noticeText = "顺序错误：必须先向用户说明权限用途（markRationaleShown），才能处理申请结果")
            }
        }
        val newState = wifi.onRequestResult(granted)
        val cap = wifi.capability()
        return update {
            it.copy(
                permissionState = newState,
                capability = cap,
                noticeText = if (granted) "已获得「位置信息」权限：可显示系统检测到的 WiFi 列表"
                else "已拒绝「位置信息」权限：降级为「只检测当前 WiFi」，不显示周边列表 ${cap.degradedReason ?: ""}".trim(),
                ssidList = if (granted) it.ssidList else emptyList()
            )
        }
    }

    fun syncPermissionState(): ConfigUiState = update {
        it.copy(
            permissionState = wifi.permissionState(),
            capability = wifi.capability(),
            noticeText = degradeNotice(wifi.capability())
        )
    }

    fun save(): SaveOutcome {
        val s = state
        val username = s.effectiveUsername()
        if (username.isBlank()) {
            val msg = "保存失败：账号不能为空"
            update { it.copy(statusText = msg, statusOk = false) }
            return SaveOutcome.Invalid(msg)
        }
        if (username.length > 512 || s.passwordInput.length > 1024 || s.effectiveLabel().length > 128) {
            val message = "保存失败：账号、密码或备注过长，请检查输入"
            update { it.copy(statusText = message, statusOk = false) }
            return SaveOutcome.Invalid(message)
        }
        if (s.passwordInput.isEmpty()) {
            val msg = "保存失败：密码不能为空"
            update { it.copy(statusText = msg, statusOk = false) }
            return SaveOutcome.Invalid(msg)
        }
        if (s.selectedSsid.isNullOrBlank()) {
            val msg = "保存失败：请选择一个 WiFi（可点「用当前连接的 WiFi」）"
            update { it.copy(statusText = msg, statusOk = false) }
            return SaveOutcome.Invalid(msg)
        }
        val plan = SavePlan(
            credential = Credential(
                label = s.effectiveLabel(),
                username = username,
                password = s.passwordInput,
                carrier = s.carrier.value,
                acId = Carrier.AC_ID    // 已冻结：字符串 "5"
            ),
            targetSsid = s.selectedSsid!!,
            label = s.effectiveLabel()
        )
        update { it.copy(statusText = "已保存：${plan.label} ↔ ${plan.targetSsid}", statusOk = true) }
        return SaveOutcome.Saved(plan)
    }

    fun loginNow(): ConfigUiState {
        val target = state.selectedSsid ?: wifi.currentSsid()
        val outcome = loginTrigger.login(target)
        return update { it.copy(busy = false) }.let { applyOutcome(outcome) }
    }

    fun applyOutcome(outcome: AuthFlowOutcome): ConfigUiState {
        val now = clock()
        return when (outcome) {
            is AuthFlowOutcome.Skipped -> {
                val result = AuthSkip.toResult(outcome)
                val alreadyOnline = top.ytu.srunautologin.auth.AuthResultStatus.isAlreadyOnline(result)
                update {
                    it.copy(
                        lastResult = result,
                        lastAttemptAtMillis = now,
                        statusOk = alreadyOnline,
                        statusText = formatStatus(result, now, alreadyOnline)
                    )
                }
            }
            is AuthFlowOutcome.Done -> update {
                it.copy(
                    lastResult = outcome.result,
                    lastAttemptAtMillis = now,
                    statusOk = outcome.result.ok ||
                        top.ytu.srunautologin.auth.AuthResultStatus.isAlreadyOnline(outcome.result),
                    statusText = formatStatus(
                        outcome.result, now,
                        top.ytu.srunautologin.auth.AuthResultStatus.isAlreadyOnline(outcome.result)
                    )
                )
            }
        }
    }

    @Synchronized
    private fun update(f: (ConfigUiState) -> ConfigUiState): ConfigUiState {
        state = f(state)
        return state
    }

    private fun degradeNotice(cap: WifiCapability): String =
        if (cap.degraded) "降级提示：${cap.degradedReason}" else ""

    companion object {
        fun portalInitialInput(store: KeyValueStore?): String = PortalConfig.read(store)

        fun validatePortalInput(raw: String): String? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) return "门户地址不能为空（示例：${PortalConfig.DEFAULT_PORTAL}）"
            if (trimmed.any { it.isWhitespace() }) return "门户地址中间不能有空格"
            if (PortalConfig.normalize(trimmed) == null) {
                return "门户地址无效：请填写 HTTP 或 HTTPS 的主机地址和可选端口，不要包含账号、路径或查询参数"
            }
            return null
        }

        fun formatStatus(result: AuthResult, atMillis: Long, alreadyOnline: Boolean = false): String {
            val time = formatTime(atMillis)
            val ok = result.ok || alreadyOnline
            val head = if (ok) "成功" else "失败（${result.failure?.displayName ?: result.code}）"
            val tail = if (ok) "" else " · ${result.code}"
            return "[$time] $head：${result.msg}$tail（阶段 ${result.stage}，${
                result.elapsedMs
            } ms）"
        }

        fun formatTime(millis: Long): String {
            val cal = java.util.Calendar.getInstance()
            cal.timeInMillis = millis
            fun two(v: Int) = if (v < 10) "0$v" else "$v"
            return "${two(cal.get(java.util.Calendar.HOUR_OF_DAY))}:" +
                "${two(cal.get(java.util.Calendar.MINUTE))}:" +
                two(cal.get(java.util.Calendar.SECOND))
        }
    }
}
