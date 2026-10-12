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

/**
 * 配置界面的纯逻辑层（不引用任何 Android View/Context，可离线测试）。
 *
 * UI 元素与需求编号对应（B2）：
 *  1. [ConfigUiState.usernameInput]   账号输入框
 *  2. [ConfigUiState.passwordInput]   密码输入框（inputType=textPassword，见 layout）
 *  3. [ConfigUiState.carrierIndex]    登录方式二选一（[CarrierOption]）
 *  4. [ConfigUiState.labelInput]      备注名（默认自动生成 = 运营商显示名）
 *  5. [ConfigUiState.ssidList]        WiFi 选择区（系统列表）+「用当前连接的 WiFi」快捷按钮
 *  6. [ConfigUiState.permissionNotice] 权限说明与降级提示
 *  7. 保存 → [ConfigViewModel.save]（写入 credentialRepository + wifiAccountMap）
 *  8. [ConfigUiState.statusText]      状态显示区（成功/失败原因/时间，失败不静默）
 *  9. 立即登录 → [ConfigViewModel.loginNow]
 * 10. [ConfigUiState.portalInput]     Portal（门户）地址输入框 → [ConfigViewModel.savePortal]
 */

/** 登录方式选项（与已冻结的 [Carrier] 取值一一对应）。 */
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

/** 一次配置界面「保存」之后的持久化动作描述（由 UI 绑定层执行真正的写入）。 */
data class SavePlan(
    val credential: Credential,
    val targetSsid: String,
    val label: String
)

/** 保存结果（失败原因不静默，直接进状态区）。 */
sealed interface SaveOutcome {
    data class Saved(val plan: SavePlan) : SaveOutcome
    data class Invalid(val message: String) : SaveOutcome
}

/** Portal 地址保存结果（非法输入给出可见提示，不静默接受）。 */
sealed interface PortalSaveOutcome {
    /** @param portal 规范化之后的 Portal 基地址（形如 `http://202.194.116.116`）。 */
    data class Saved(val portal: String) : PortalSaveOutcome

    data class Invalid(val message: String) : PortalSaveOutcome
}

/** 密码输入框的内容统一口径（Trim 去首尾空白）。 */
object InputRules {
    fun normalizeUsername(raw: String): String = raw.trim()

    /**
     * 用户名补全运营商后缀：参考实现 srun-login.js 明确「不擅自拼接后缀」，后缀由页面下拉框决定。
     * 本应用据此按用户选择的登录方式补全（用户已自带 @ 时原样保留）。
     */
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

/** 配置界面的完整状态快照（不可变；ViewModel 每次变更产出新实例）。 */
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
    /** 元素 10：Portal（门户）地址输入框的当前文本（保存时校验并持久化）。 */
    val portalInput: String = PortalConfig.DEFAULT_PORTAL,
    val busy: Boolean = false
) {
    val carrier: CarrierOption get() = CarrierOption.entries[carrierIndex.coerceIn(0, CarrierOption.entries.size - 1)]

    /** 是否处于「权限被拒 → 只检测当前 WiFi」的降级状态（界面必须明确提示）。 */
    val degraded: Boolean get() = capability.degraded

    fun effectiveLabel(): String = InputRules.labelOrDefault(labelInput, carrier)

    fun effectiveUsername(): String = InputRules.applyCarrierDomain(usernameInput, carrier)
}

/**
 * WiFi 交互端口：把 WifiSnapshot / WifiPermissionFlow 挡在接口后面，
 * 使 ViewModel 可在 JVM 上用假实现离线测试（含权限顺序断言）。
 */
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

/** 认证触发端口（真机实现：调用 flow.AuthFlow，并把结果回调给状态区）。 */
interface LoginTrigger {
    /** @param targetSsid 目标 SSID（B8 匹配判据） */
    fun login(targetSsid: String?): AuthFlowOutcome

    companion object {
        val NOOP: LoginTrigger = object : LoginTrigger {
            override fun login(targetSsid: String?): AuthFlowOutcome =
                AuthFlowOutcome.Skipped(top.ytu.srunautologin.flow.AuthSkipReason.NO_CURRENT_SSID, null, targetSsid)
        }
    }
}

/**
 * 配置界面 ViewModel（纯逻辑，无 Android 依赖）。
 *
 * 权限流程顺序（用户需求原文「先说明权限用途，然后申请权限，若不同意则只检查当前 wifi」）：
 *  1. [permissionExplanation] 取说明文案 → 2. [beginPermissionRequest] 记录「已说明」（markRationaleShown）
 *  → 3. Activity 弹系统对话框 → 4. [onPermissionResult] 处理结果并更新能力/降级提示。
 * 顺序被硬性固定：未调用过 [beginPermissionRequest] 就调用 [onPermissionResult] 会返回失败提示，不会静默通过。
 */
class ConfigViewModel(
    private val wifi: WifiUiPort,
    private val loginTrigger: LoginTrigger = LoginTrigger.NOOP,
    /**
     * Portal 地址配置存储（可空：纯逻辑离线用例可不注入，此时按代码默认值工作）。
     * **本类不直接碰 SharedPreferences/Context** —— 真机由 Activity 在 onCreate 之后注入。
     */
    private val portalStore: KeyValueStore? = null,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {

    var state: ConfigUiState = ConfigUiState(
        labelInput = CarrierOption.YTU.displayName,
        permissionState = wifi.permissionState(),
        capability = wifi.capability(),
        rationaleText = wifi.explainText,
        // 用户保存的值优先；缺失/非法时回落到代码默认值（PortalConfig.DEFAULT_PORTAL）
        portalInput = portalInitialInput(portalStore)
    )
        private set

    private var rationaleMarked = false

    /* ------------------------- 元素 1/2/4：文本输入 ------------------------- */

    fun setUsername(value: String): ConfigUiState = update { it.copy(usernameInput = value) }

    fun setPassword(value: String): ConfigUiState = update { it.copy(passwordInput = value) }

    fun setLabel(value: String): ConfigUiState = update { it.copy(labelInput = value, labelTouched = true) }

    /* ------------------------- 元素 10：Portal 地址 ------------------------- */

    /** 输入框文本变化 → 写回状态（校验与持久化在 [savePortal] 里做，不在文本监听里做）。 */
    fun setPortal(value: String): ConfigUiState = update { it.copy(portalInput = value) }

    /**
     * 保存 Portal 地址：校验 → 写入键值存储 → 状态区给出可见反馈。
     *
     * 关键约定：
     *  - **非法输入不写脏值、不覆盖已保存的旧值**，返回 [PortalSaveOutcome.Invalid] 并把原因写进状态区；
     *  - 存储缺失（离线纯逻辑用例）时返回失败提示，**不静默假装已保存**；
     *  - 归一化（去空白 / 去尾斜杠 / 补 `http://`）由已冻结的
     *    [top.ytu.srunautologin.auth.SrunRequestBuilder.normalizePortal] 权威实现完成，本层不重复实现。
     */
    fun savePortal(): PortalSaveOutcome {
        val raw = state.portalInput
        val invalid = validatePortalInput(raw)
        if (invalid != null) {
            update { it.copy(statusText = invalid, statusOk = false) }
            return PortalSaveOutcome.Invalid(invalid)
        }
        val store = portalStore
            ?: run {
                val msg = "保存失败：Portal 地址存储不可用（未注入 KeyValueStore）"
                update { it.copy(statusText = msg, statusOk = false) }
                return PortalSaveOutcome.Invalid(msg)
            }
        val saved = PortalConfig.write(store, raw)
            ?: run {
                val msg = "保存失败：Portal 地址非法（$raw），已保留原值"
                update { it.copy(statusText = msg, statusOk = false) }
                return PortalSaveOutcome.Invalid(msg)
            }
        // 把规范化后的地址回填到状态（界面同步显示 http://主机 形态）
        update {
            it.copy(
                portalInput = saved,
                statusText = "已保存 Portal 地址：$saved（重启应用后仍然生效）",
                statusOk = true
            )
        }
        return PortalSaveOutcome.Saved(saved)
    }

    /* ------------------------- 元素 3：登录方式二选一 ------------------------- */

    fun selectCarrier(index: Int): ConfigUiState = update { s ->
        val newCarrier = CarrierOption.entries[index.coerceIn(0, CarrierOption.entries.size - 1)]
        val autoLabel = !s.labelTouched || s.labelInput == s.carrier.displayName
        s.copy(
            carrierIndex = CarrierOption.entries.indexOf(newCarrier),
            labelInput = if (autoLabel) newCarrier.displayName else s.labelInput
        )
    }

    /* ------------------------- 元素 5：WiFi 选择区 ------------------------- */

    /**
     * WiFi 数据的统一提示（wifi-fix1 / 缺陷 R4、任务 B）。
     *
     * 旧实现在「权限已授予但系统读不到」时说「（未连接、WiFi 关闭或权限被拒）」——与状态行的绿色
     * 「已授权」自相矛盾，并把用户指向错误方向。这里按事实分支：
     *  - 权限不可扫描 → 沿用既有降级文案；
     *  - 权限没问题但**一条都读不到** → 明确说「已获得权限，但系统未返回…」并指向「位置信息」总开关；
     *  - 其余情况 → 沿用既有降级文案（正常时为空串）。
     */
    private fun wifiDataNotice(cap: WifiCapability, noDataAtAll: Boolean): String = when {
        !cap.canScanList -> degradeNotice(cap)
        noDataAtAll ->
            "已获得权限，但系统未返回 WiFi 信息：请先确认系统「位置信息」总开关已开启，并确认本应用已开启「精确位置」（Android 12+ 起 WiFi 名称与列表属于位置信息，关闭精确位置会读不到）"
        else -> degradeNotice(cap)
    }

    /** 刷新系统检测到的 WiFi 列表；权限被拒时列表为空并要求界面显示降级提示。 */
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

    /** 「使用当前连接 wifi」快捷按钮。 */
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

    /** 手动在列表中选定 WiFi。 */
    fun selectSsid(ssid: String): ConfigUiState = update { it.copy(selectedSsid = ssid) }

    /* ------------------------- 元素 6：权限说明流程 ------------------------- */

    /** 第 1 步：取说明文案（UI 展示给用户）。 */
    fun permissionExplanation(): String = wifi.explainText

    /** 第 2 步：UI 已展示说明，调用原因说明标记（对应 markRationaleShown()）。 */
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

    /** 第 4 步：系统弹窗结果（对应 onRequestResult）。拒绝 → 降级为只检测当前 WiFi 并显式提示。 */
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

    /** 从系统设置返回后重新同步（对应 syncGrantedPermissions 的调用前状态刷新）。 */
    fun syncPermissionState(): ConfigUiState = update {
        it.copy(
            permissionState = wifi.permissionState(),
            capability = wifi.capability(),
            noticeText = degradeNotice(wifi.capability())
        )
    }

    /* ------------------------- 元素 7：保存 ------------------------- */

    /**
     * 纯逻辑校验 + 产出写入计划；真正的写入由 Activity 调用
     * SrunStorage.credentialRepository / wifiAccountMap 完成。
     */
    fun save(): SaveOutcome {
        val s = state
        val username = s.effectiveUsername()
        if (username.isBlank()) {
            val msg = "保存失败：账号不能为空"
            update { it.copy(statusText = msg, statusOk = false) }
            return SaveOutcome.Invalid(msg)
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
            targetSsid = s.selectedSsid!!.trim(),
            label = s.effectiveLabel()
        )
        update { it.copy(statusText = "已保存：${plan.label} ↔ ${plan.targetSsid}", statusOk = true) }
        return SaveOutcome.Saved(plan)
    }

    /* ------------------------- 元素 8/9：状态区与立即登录 ------------------------- */

    fun loginNow(): ConfigUiState {
        val target = state.selectedSsid ?: wifi.currentSsid()
        val outcome = loginTrigger.login(target)
        return update { it.copy(busy = false) }.let { applyOutcome(outcome) }
    }

    /** 把认证结果写入状态区（成功/失败原因/时间，失败不静默）。 */
    fun applyOutcome(outcome: AuthFlowOutcome): ConfigUiState {
        val now = clock()
        return when (outcome) {
            is AuthFlowOutcome.Skipped -> {
                val result = AuthSkip.toResult(outcome)
                update {
                    it.copy(
                        lastResult = result,
                        lastAttemptAtMillis = now,
                        statusOk = false,
                        statusText = formatStatus(result, now)
                    )
                }
            }
            is AuthFlowOutcome.Done -> update {
                it.copy(
                    lastResult = outcome.result,
                    lastAttemptAtMillis = now,
                    statusOk = outcome.result.ok,
                    statusText = formatStatus(outcome.result, now)
                )
            }
        }
    }

    private fun update(f: (ConfigUiState) -> ConfigUiState): ConfigUiState {
        state = f(state)
        return state
    }

    private fun degradeNotice(cap: WifiCapability): String =
        if (cap.degraded) "降级提示：${cap.degradedReason}" else ""

    companion object {
        /**
         * 输入框初值：优先显示用户已保存的值（经校验规范化），否则显示代码默认值。
         * 存储里的值若非法（历史脏数据），按「缺失」处理并回落到默认值——界面绝不显示一个保存必失败的值。
         */
        fun portalInitialInput(store: KeyValueStore?): String = PortalConfig.read(store)

        /** 保存前的可见校验：返回 null 表示合法；否则返回给用户看的原因（含原始输入）。 */
        fun validatePortalInput(raw: String): String? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) return "Portal 地址不能为空（示例：${PortalConfig.DEFAULT_PORTAL}）"
            if (trimmed.any { it.isWhitespace() }) return "Portal 地址中间不能有空格：$trimmed"
            if (PortalConfig.normalize(trimmed) == null) {
                return "Portal 地址非法：$trimmed（只支持主机名或 IPv4，可带 http:// 前缀，不要带路径）"
            }
            return null
        }

        /** 状态区文本格式：`[时间] 成功/失败原因`（失败不静默）。 */
        fun formatStatus(result: AuthResult, atMillis: Long): String {
            val time = formatTime(atMillis)
            val head = if (result.ok) "成功" else "失败（${result.failure?.displayName ?: result.code}）"
            val tail = if (result.ok) "" else " · ${result.code}"
            return "[$time] $head：${result.msg}$tail（阶段 ${result.stage}，${
                result.elapsedMs
            } ms）"
        }

        /** 本地时间 HH:mm:ss（不依赖 java.time 的时区配置）。 */
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
