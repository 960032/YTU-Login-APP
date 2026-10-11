package top.ytu.srunautologin.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import top.ytu.srunautologin.R
import top.ytu.srunautologin.auth.SrunAuthClient
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.CoreWifiSnapshotPort
import top.ytu.srunautologin.flow.LoginTrigger
import top.ytu.srunautologin.flow.MapWifiAccountLookup
import top.ytu.srunautologin.flow.RepositoryCredentialLookup
import top.ytu.srunautologin.net.AndroidWifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.platform.AndroidWifiSource
import top.ytu.srunautologin.platform.SrunStorage

/**
 * 配置界面 Activity —— **只做薄绑定**：所有业务判断都在 [ConfigViewModel]（纯逻辑，可离线测试）。
 *
 * 零第三方 UI 依赖：只用 android.app.Activity + 系统原生 View + 系统主题（res/values/themes.xml）。
 *
 * 绑定清单：
 *  - 账号/密码/备注名   → ViewModel.setUsername / setPassword / setLabel
 *  - 登录方式 Spinner   → ViewModel.selectCarrier
 *  - WiFi 列表 + 「用当前连接的 WiFi」 → ViewModel.refreshSsidList / useCurrentSsid
 *  - 权限流程           → [PermissionPort]（顺序：说明 → markRationaleShown → 系统弹窗 → onRequestResult）
 *  - 保存               → ViewModel.save() 产出 SavePlan → SrunStorage.credentialRepository / wifiAccountMap
 *  - 立即登录           → ViewModel.loginNow() → flow.AuthFlow（B8 匹配后才发请求）
 *  - 状态区             → ViewModel.state.statusText（失败不静默）
 */
class MainActivity : Activity() {

    private lateinit var viewModel: ConfigViewModel
    private lateinit var authFlow: AuthFlow

    private lateinit var editUsername: EditText
    private lateinit var editPassword: EditText
    private lateinit var spinnerCarrier: Spinner
    private lateinit var editLabel: EditText
    private lateinit var btnUseCurrentWifi: Button
    private lateinit var ssidList: LinearLayout
    private lateinit var textPermissionNotice: TextView
    private lateinit var btnRequestPermission: Button
    private lateinit var btnSave: Button
    private lateinit var textStatus: TextView
    private lateinit var btnLoginNow: Button
    private lateinit var editNewSsid: EditText

    /** 权限端口：把系统 Activity 能力暴露给 ViewModel；顺序由 ViewModel 强制执行。 */
    private val permissionPort = object : PermissionPort {
        private val flow = AndroidWifiPermissionFlow(this@MainActivity)

        override val explainText: String get() = flow.explainText

        override fun requiredPermissions(): List<String> = flow.requiredPermissions()

        override fun state(): WifiPermissionState = flow.state()

        override fun markRationaleShown() = flow.markRationaleShown()

        override fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState =
            flow.onRequestResult(outcome)

        override fun requestPermissions() {
            ActivityCompatBridge.request(this@MainActivity, flow.requiredPermissions())
        }
    }

    private val wifiUiPort: WifiUiPort = object : PermissionUiAdapter(permissionPort) {
        private val core = WifiSnapshotCore(
            AndroidWifiSource(this@MainActivity),
            AndroidWifiPermissionFlow(this@MainActivity)
        )

        override fun currentSsid(): String? = core.currentSsid()

        override fun scanSsidList(): List<String> = core.scanSsidList()
    }

    private val loginTrigger = object : LoginTrigger {
        override fun login(targetSsid: String?): AuthFlowOutcome = authFlow.run(targetSsid)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        editUsername = findViewById(R.id.edit_username)
        editPassword = findViewById(R.id.edit_password)
        spinnerCarrier = findViewById(R.id.spinner_carrier)
        editLabel = findViewById(R.id.edit_label)
        btnUseCurrentWifi = findViewById(R.id.btn_use_current_wifi)
        ssidList = findViewById(R.id.ssid_list)
        textPermissionNotice = findViewById(R.id.text_permission_notice)
        btnRequestPermission = findViewById(R.id.btn_request_permission)
        btnSave = findViewById(R.id.btn_save)
        textStatus = findViewById(R.id.text_status)
        btnLoginNow = findViewById(R.id.btn_login_now)
        editNewSsid = findViewById(R.id.edit_new_ssid)

        buildAuthFlow()
        buildViewModel()
        bindViews()
        refreshSsidList()
    }

    /** 认证链路装配：存储（已冻结）+ WiFi 快照（已冻结）+ 认证客户端（本任务新增）。 */
    private fun buildAuthFlow() {
        authFlow = AuthFlow(
            credentials = RepositoryCredentialLookup(SrunStorage.credentialRepository(this)),
            wifiMap = MapWifiAccountLookup(SrunStorage.wifiAccountMap(this)),
            wifiSnapshot = CoreWifiSnapshotPort(
                WifiSnapshotCore(AndroidWifiSource(this), AndroidWifiPermissionFlow(this))
            ),
            transport = SrunAuthClient()
        )
    }

    private fun buildViewModel() {
        viewModel = ConfigViewModel(wifiUiPort, loginTrigger)
        spinnerCarrier.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            CarrierOption.displayNames()
        ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
    }

    private fun bindViews() {
        editUsername.setText(viewModel.state.usernameInput)
        editLabel.setText(viewModel.state.labelInput)

        // 元素 1/2/4：输入即时回写 ViewModel（业务判断不在这里做）
        editUsername.addTextChangedListener(SimpleTextWatcher { viewModel.setUsername(it) })
        editPassword.addTextChangedListener(SimpleTextWatcher { viewModel.setPassword(it) })
        editLabel.addTextChangedListener(SimpleTextWatcher { viewModel.setLabel(it) })
        editNewSsid.addTextChangedListener(SimpleTextWatcher { })

        // 元素 3：登录方式二选一
        spinnerCarrier.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                viewModel.selectCarrier(position)
                editLabel.setText(viewModel.state.labelInput)
                render()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }

        // 元素 5：用当前连接的 WiFi（快捷按钮）
        btnUseCurrentWifi.setOnClickListener {
            viewModel.useCurrentSsid()
            render()
        }

        // 元素 6：权限说明流程（严格顺序）
        btnRequestPermission.setOnClickListener {
            // 第 1 步：展示说明文案
            AlertDialog.Builder(this)
                .setTitle(R.string.permission_explain_title)
                .setMessage(viewModel.permissionExplanation())
                .setPositiveButton(R.string.permission_grant_ok) { _, _ ->
                    // 第 2 步：markRationaleShown（在 ViewModel.beginPermissionRequest 内部）
                    viewModel.beginPermissionRequest()
                    val required = permissionPort.requiredPermissions()
                    if (required.isEmpty()) {
                        // 当前系统版本无需运行时权限（API < 27）：直接按授予处理，状态保持一致
                        viewModel.onPermissionResult(true)
                    } else {
                        // 第 3 步：系统权限弹窗（结果回到 onRequestPermissionsResult）
                        permissionPort.requestPermissions()
                    }
                    render()
                }
                .setNegativeButton(R.string.permission_grant_cancel) { _, _ ->
                    // 说明阶段被拒：等同拒绝 → 第 4 步 onRequestResult(DENIED) → 降级为只检测当前 WiFi
                    viewModel.beginPermissionRequest()
                    viewModel.onPermissionResult(false)
                    render()
                }
                .show()
        }

        // 元素 7：保存（写入已冻结的存储）
        btnSave.setOnClickListener {
            when (val outcome = viewModel.save()) {
                is SaveOutcome.Invalid -> toast(outcome.message)
                is SaveOutcome.Saved -> {
                    SrunStorage.credentialRepository(this).upsert(outcome.plan.credential)
                    SrunStorage.wifiAccountMap(this).bind(outcome.plan.targetSsid, outcome.plan.label)
                    SrunStorage.credentialRepository(this).select(outcome.plan.label)
                    toast(getString(R.string.save_done, outcome.plan.label, outcome.plan.targetSsid))
                }
            }
            render()
        }

        // 元素 9：立即登录（B8 在 AuthFlow 内判定；SSID 不匹配时零请求）
        btnLoginNow.setOnClickListener {
            viewModel.loginNow()
            render()
        }
    }

    /** 元素 5：刷新系统检测到的 WiFi 列表（权限被拒时为空列表 + 降级提示）。 */
    private fun refreshSsidList() {
        viewModel.refreshSsidList()
        render()
    }

    /** 元素 8：状态区渲染（失败不静默：文本 + 颜色 + Toast）。 */
    private fun render() {
        val s = viewModel.state
        textStatus.text = s.statusText
        textStatus.setTextColor(
            if (s.statusOk) 0xFF2E7D32.toInt() else 0xFFC62828.toInt()
        )
        if (s.lastResult != null && !s.statusOk) {
            Toast.makeText(this, s.statusText, Toast.LENGTH_LONG).show()
        }

        textPermissionNotice.text = buildString {
            if (s.rationaleShown) append(s.rationaleText).append('\n')
            append(s.noticeText)
            if (s.degraded) {
                append('\n').append(getString(R.string.degraded_prefix))
                    .append('：').append(s.permissionState.name)
            }
        }

        ssidList.removeAllViews()
        for (ssid in s.ssidList) {
            val check = CheckBox(this)
            check.text = ssid
            check.isChecked = ssid == s.selectedSsid
            check.setOnClickListener {
                viewModel.selectSsid(ssid)
                render()
            }
            ssidList.addView(check)
        }
        if (s.ssidList.isEmpty() && s.degraded) {
            val tv = TextView(this)
            tv.text = getString(R.string.degraded_no_list)
            ssidList.addView(tv)
        }
    }

    /** 第 4 步：系统弹窗结果 → onRequestResult（拒绝则降级，界面显式提示）。 */
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_WIFI) return
        val granted = grantResults.isNotEmpty() &&
            grantResults.all { it == PackageManager.PERMISSION_GRANTED }
        viewModel.onPermissionResult(granted)
        render()
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private companion object {
        const val REQ_WIFI = 1001
    }
}

/** 极简 TextWatcher（避免匿名对象样板）。 */
private class SimpleTextWatcher(private val onChanged: (String) -> Unit) :
    android.text.TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
    override fun afterTextChanged(s: android.text.Editable?) = onChanged(s?.toString().orEmpty())
}

/** 系统权限申请封装：requestPermissions 是 Activity（API 23+）自带方法，无需 AndroidX。 */
private object ActivityCompatBridge {
    fun request(activity: Activity, permissions: List<String>) {
        if (permissions.isEmpty()) return
        activity.requestPermissions(permissions.toTypedArray(), 1001)
    }
}
