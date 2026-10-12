package top.ytu.srunautologin.ui

import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState

/**
 * 界面配置常量：把 B2 要求的所有界面元素、元素顺序、控件类型集中声明，
 * 使「界面是否具备 N 个元素」可在 JVM 上离线核对（见 verify-common-client 的 UI 结构检查）。
 *
 * UI 元素 ↔ 需求编号（B2）：
 *  1 | 账号输入     | EditText  | id=edit_username
 *  2 | 密码输入     | EditText  | id=edit_password（inputType=textPassword）
 *  3 | 登录方式二选一 | Spinner   | id=spinner_carrier（烟台大学 / 中国移动）
 *  4 | 备注名       | EditText  | id=edit_label
 *  5 | WiFi 选择区   | Button + LinearLayout | id=btn_use_current_wifi / id=ssid_list（系统列表）
 *  6 | 权限说明流程  | TextView + Button | id=text_permission_notice / id=btn_request_permission
 * 6a | 权限状态（与说明分离）| TextView | id=text_permission_state（未授权=红 / 已授权=绿，颜色由代码按状态设置）
 *  7 | 保存         | Button    | id=btn_save
 *  8 | 状态显示区    | TextView  | id=text_status
 *  9 | 立即登录      | Button    | id=btn_login_now
 * 10 | Portal 地址   | EditText + Button | id=edit_portal / id=btn_save_portal
 *    （门户地址可配置：不同校区地址不同，用户填的值持久化并优先于代码默认值；
 *      index 追加在末尾，**原有 1..9 的编号与含义一律不变**，见 ClientChecks UI-1 的下界断言）
 */
object UiSpec {

    /** 界面元素声明（顺序即界面自上而下的顺序）。 */
    val ELEMENTS: List<UiElement> = listOf(
        UiElement(1, "账号输入", "EditText", "edit_username", "B2"),
        UiElement(2, "密码输入", "EditText", "edit_password", "B2（inputType=textPassword）"),
        UiElement(3, "登录方式二选一", "Spinner", "spinner_carrier", "B2（烟台大学/中国移动）"),
        UiElement(4, "备注名", "EditText", "edit_label", "B2"),
        UiElement(5, "WiFi 选择区（系统列表 + 使用当前连接 wifi）", "LinearLayout+Button", "ssid_list/btn_use_current_wifi", "B2"),
        UiElement(6, "权限说明与申请", "TextView+Button", "text_permission_notice/btn_request_permission", "权限策略"),
        // 用户真机反馈（ui-fix1）：权限「说明」与「状态」原来挤在同一个 TextView 里，分辨不出。
        // 这里如实登记新增的独立状态行；index 用 6a 表示「元素 6 的拆分」，**不重排既有 7..10 的编号**，
        // 新增元素同样不触发 ClientChecks UI-1 的子集断言（它是「必需元素子集 + 数量下界」）。
        UiElement(6, "权限状态（与说明分离，红/绿随状态变化）", "TextView", "text_permission_state", "用户真机反馈：权限获取与否不明显"),
        UiElement(7, "保存", "Button", "btn_save", "B2"),
        UiElement(8, "状态显示区", "TextView", "text_status", "B5"),
        UiElement(9, "立即登录", "Button", "btn_login_now", "B5/B8"),
        UiElement(10, "Portal 地址（门户地址可配置）", "EditText+Button", "edit_portal/btn_save_portal", "用户需求：地址可配置"),
        // 【元素 11（morning1 任务）】用户新需求：每天 6:00 自动登录 + 常驻通知 + 应用内启停开关 + 权限描述文本。
        // 追加在末尾，**原有 1..10 的编号与含义一律不变**（UI-1 是「必需元素子集 + 数量下界」断言，不重排）。
        // 【元素 12（accountsel1 任务）】用户新需求：添加「账号选择」按钮 + 弹窗（多选 + 删除）。
        // 追加在末尾，**原有 1..11 的编号与含义一律不变**（UI-1 是「必需元素子集 + 数量下界」断言，不重排）。
        UiElement(
            12,
            "账号选择（多选勾选生效 + 逐条删除）",
            "Button+AlertDialog(CheckBox+TextView+TextView+TextView)",
            "btn_choose_account",
            "用户需求：添加账号选择按钮 → 弹出「选择生效账号」弹框，列出已保存账号与对应网络，" +
                "每条最左勾选框、偏左账户、偏右网络、最右蓝色「删除」；勾选任意数量参与每天早上 6:00 的网络匹配。"
        ),
        UiElement(
            11,
            "早上自动登录：启停开关 + 状态行 + 自启动权限文案 + 一键跳转系统设置",
            "Button+TextView+TextView+Button",
            "btn_toggle_auto_login/text_morning_status/text_autostart_notice/btn_open_autostart_settings",
            "用户需求：点击(启用/停用)自动登录 + 登录任务需要自启动权限，该权限用于每天早上的自动唤起。"
        )
    )

    /** 状态区必须能表达的信息类别（B5：成功/失败原因/时间）。 */
    val STATUS_FIELDS: List<String> = listOf("成功或失败", "失败原因（错误分类 + 错误码 + 服务端信息）", "时间（HH:mm:ss）", "阶段 stage", "耗时 elapsedMs")

    /** 失败原因不得静默：任何非 ok 结果都必须写入状态区并可见。 */
    const val FAILURE_MUST_BE_VISIBLE: Boolean = true
}

/** 一条界面元素声明。 */
data class UiElement(
    val index: Int,
    val name: String,
    val viewType: String,
    val viewId: String,
    val requirement: String
) {
    override fun toString(): String = "$index. $name [$viewType] #$viewId（$requirement）"
}

/**
 * 权限申请结果的界面端口（Activity 实现，ViewModel 依赖）。
 *
 * 顺序被接口固化（用户需求原文：先说明权限用途 → 再申请 → 不同意则只检查当前 wifi）：
 *  [explainText] 取文案 → [markRationaleShown] 记录已说明 → [requestPermissions] 弹系统对话框
 *  → [onRequestResult] 处理结果。[requestPermissions] 内部必须先调 markRationaleShown，否则会抛异常。
 */
interface PermissionPort {
    val explainText: String
    fun requiredPermissions(): List<String>
    fun state(): WifiPermissionState
    fun markRationaleShown()
    fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState
    fun requestPermissions()
    fun capabilityDegradedReason(): String?
}

/**
 * 从接口 [PermissionPort] 到界面 [WifiUiPort] 的适配器（纯逻辑，可离线测试顺序）。
 *
 * 关键点：View 层的 ViewModel 只调用本适配器，因此「先说明再申请」的顺序在任何 Activity 上都成立；
 * 顺序测试在 JVM 上用假端口即可验证。
 *
 * WiFi 快照相关成员（currentSsid / scanSsidList）由子类补齐（真机在 MainActivity 里挂 WifiSnapshotCore）。
 */
abstract class PermissionUiAdapter(private val port: PermissionPort) : WifiUiPort {

    override val explainText: String get() = port.explainText

    override fun requiredPermissions(): List<String> = port.requiredPermissions()

    override fun permissionState(): WifiPermissionState = port.state()

    override fun capability(): top.ytu.srunautologin.net.WifiCapability =
        top.ytu.srunautologin.net.WifiPermissionPolicy.capability(port.state())

    override fun markRationaleShown() = port.markRationaleShown()

    override fun onRequestResult(granted: Boolean): WifiPermissionState =
        port.onRequestResult(
            if (granted) WifiPermissionRequestOutcome.GRANTED else WifiPermissionRequestOutcome.DENIED
        )
}
