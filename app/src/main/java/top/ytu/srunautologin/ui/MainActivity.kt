package top.ytu.srunautologin.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
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
import top.ytu.srunautologin.flow.MapWifiAccountLookup
import top.ytu.srunautologin.flow.RepositoryCredentialLookup
import top.ytu.srunautologin.flow.StoredPortalProvider
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.platform.AndroidWifiPermissionFlow
import top.ytu.srunautologin.platform.AndroidWifiSource
import top.ytu.srunautologin.platform.SrunStorage
import java.io.File

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
    private lateinit var editPortal: EditText
    private lateinit var btnSavePortal: Button

    /**
     * Portal 地址配置存储（元素 10）。
     *
     * **crashfix2 约束**：`SrunStorage.keyValueStore(this)` 内部会取
     * `context.applicationContext`（AndroidWiring.kt:233 → SharedPreferences），
     * 而这在 `MainActivity.<init>` 阶段不可用（Activity 尚未 attach，mBase 为 null → NPE）。
     * 因此这里用 `by lazy`：求值推迟到 `onCreate` 内 `bindViews()` 首次访问时，那时 Activity 已 attach。
     * **不允许**把 `SrunStorage.keyValueStore(...)` 直接写成 `val` 实例属性初始化器。
     */
    private val portalStore by lazy { SrunStorage.keyValueStore(this) }

    /**
     * 权限端口：把系统 Activity 能力暴露给 ViewModel；顺序由 ViewModel 强制执行。
     *
     * **crashfix2：必须 `by lazy`（延迟到首次访问）** —— 原来是构造期求值的
     * `private val permissionPort = object : PermissionPort { ... }`，它内部的
     * `AndroidWifiPermissionFlow(this@MainActivity)`（下一行）会在 **MainActivity.<init>** 阶段执行
     * `context.applicationContext`（AndroidWiring.kt 中 `AndroidWifiPermissionFlow.<init>` 的
     * `private val appContext = context.applicationContext`）。那一刻 `Activity.attachBaseContext()`
     * 还没跑，Activity 这个 ContextWrapper 的 mBase 仍为 null，于是
     * `ContextWrapper.getApplicationContext()` 抛 NPE。真机 logcat 链路（逐字）：
     *   MainActivity.<init>(MainActivity.kt:65) → MainActivity$permissionPort$1.<init>(MainActivity.kt:66)
     *   → AndroidWifiPermissionFlow.<init>(AndroidWiring.kt:119) → ContextWrapper.getApplicationContext
     * 改成 `by lazy`（默认 SYNCHRONIZED，线程安全）后，求值推迟到 `onCreate` 内 `buildViewModel()`
     * 首次访问本属性时——那时 Activity 已 attach，`applicationContext` 可用，NPE 消除。
     * 注意：访问时机与改前一致（仍是 onCreate 里），只是**求值时刻**从构造期挪到了那一刻。
     */
    private val permissionPort: PermissionPort by lazy {
        object : PermissionPort {
            private val flow = AndroidWifiPermissionFlow(this@MainActivity)

            override val explainText: String get() = flow.explainText

            override fun requiredPermissions(): List<String> = flow.requiredPermissions()

            override fun state(): WifiPermissionState = flow.state()

            override fun markRationaleShown() = flow.markRationaleShown()

            override fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState =
                flow.onRequestResult(outcome)

            /** 能力降级原因：与 PermissionUiAdapter.capability() 同源（都来自 WifiPermissionPolicy.capability）。 */
            override fun capabilityDegradedReason(): String? =
                WifiPermissionPolicy.capability(flow.state()).degradedReason

            override fun requestPermissions() {
                ActivityCompatBridge.request(this@MainActivity, flow.requiredPermissions())
            }
        }
    }

    /**
     * WiFi 列表端口。**crashfix2：同样必须 `by lazy`** —— 原为构造期求值，它有三条构造期路径会撞同一个 NPE：
     *  1) 父类构造参数 `PermissionUiAdapter(permissionPort)` 求值 → 立即初始化 permissionPort → 同上；
     *  2) 类体属性 `AndroidWifiSource(this@MainActivity)` 构造期执行 `context.applicationContext`；
     *  3) 类体属性 `AndroidWifiPermissionFlow(this@MainActivity)` 构造期执行 `context.applicationContext`。
     * `by lazy` 后整棵对象图（端口 + WifiSnapshotCore + 两个 Android 边界实现）都推迟到 onCreate
     * 首次访问时构建，此时 Activity 已 attach。
     */
    private val wifiUiPort: WifiUiPort by lazy {
        object : PermissionUiAdapter(permissionPort) {
            private val core = WifiSnapshotCore(
                AndroidWifiSource(this@MainActivity),
                AndroidWifiPermissionFlow(this@MainActivity)
            )

            override fun currentSsid(): String? = core.currentSsid()

            override fun scanSsidList(): List<String> = core.scanSsidList()
        }
    }

    /**
     * 立即登录触发器。**crashfix2 排查结论：无风险，保持原样、不加 `by lazy`** ——
     * 构造期只创建一个匿名对象（不触碰 Context / 系统服务 / 资源）；它对 `authFlow` 的引用只出现在
     * `login()` 的**方法体**内，而 `authFlow` 是 `lateinit var`（构造期没有初值，:51），
     * 到「立即登录」被点击时才读取。构造期求值的是「对象本身」，不是方法体。
     */
    private val loginTrigger: LoginTrigger = object : LoginTrigger {
        override fun login(targetSsid: String?): AuthFlowOutcome = authFlow.run(targetSsid)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // 说明（crashfix1 任务 A）：setContentView + 下面这 15 个 findViewById **故意留在 try 之外**。
        // 依据 artifacts/crash-audit1/audit-report.md：布局与 id 已逐个核对匹配，这段调用不依赖权限、
        // 不访问磁盘、不取系统服务，不在「可能抛异常」的清单里；把它们一起包住只会掩盖布局类错误。
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
        editPortal = findViewById(R.id.edit_portal)
        btnSavePortal = findViewById(R.id.btn_save_portal)

        // 启动兜底（crashfix1 任务 A）：这条同步栈上有 8 处系统调用（getSharedPreferences /
        // checkSelfPermission / getSystemService / getScanResults / getConnectionInfo），
        // 任意一处抛异常在旧代码里都会直接终止 onCreate，窗口来不及绘制 → 表现为「纯白后瞬间缩回」。
        // 这里把整条链兜住：真实崩溃点变成 logcat 一条栈 + filesDir 一个崩溃文件，而不是静默闪退。
        try {
            buildAuthFlow()
            buildViewModel()
            bindViews()
            refreshSsidList()
        } catch (e: Throwable) {
            // ① 先写 logcat（含完整栈）—— 这是拿到真实崩溃点的第一通道
            Log.e(TAG, "启动失败", e)
            // ② 再落盘到 filesDir（纯排查用；写日志自身失败也必须被吞掉，绝不二次崩溃）
            writeStartupCrashLog(e)
            // ③ 再尝试把错误显示到界面：textStatus 是 lateinit，未经 findViewById 赋值前不能碰
            if (this::textStatus.isInitialized) {
                val message = "启动失败：" + e.javaClass.simpleName + "：" + (e.message ?: "无 message") +
                    "\n详情见 files/" + CRASH_FILE + "（logcat 标签 " + TAG + "）"
                runOnUiThread {
                    try {
                        textStatus.text = message
                    } catch (t: Throwable) {
                        Log.e(TAG, "显示启动失败信息时再次异常（已忽略）", t)
                    }
                }
            }
            // ④ 立即返回：不继续跑剩余初始化，避免「View 已绑、ViewModel 未建」这类半初始化状态
            return
        }
    }

    /**
     * 写启动崩溃日志到 `filesDir/crash-startup.txt`（排查专用）。
     *
     * 三条硬约束：
     *  1) 本方法**绝不能**把异常抛回调用方 —— 写日志失败再崩一次就失去了兜底的意义，故内部整体自吞；
     *  2) 日志只含诊断信息（异常类型 / message / 栈）与时间戳，**不含**账号与密码
     *     （栈帧只有包名与行号；凭据是从文件读出来的值，不会出现在异常 message 里）；
     *  3) 用 `File(filesDir, ...)` 直写应用私有目录，不新增任何依赖。
     */
    private fun writeStartupCrashLog(e: Throwable) {
        try {
            val text = buildString {
                append("time=").append(System.currentTimeMillis()).append('\n')
                append("exception=").append(e.javaClass.name).append('\n')
                append("message=").append(e.message ?: "无").append("\n\n")
                append("stack=\n")
                append(Log.getStackTraceString(e))
            }
            File(filesDir, CRASH_FILE).writeText(text)
        } catch (t: Throwable) {
            Log.e(TAG, "写启动崩溃日志失败（已忽略，不再抛出）", t)
        }
    }

    /** 认证链路装配：存储（已冻结）+ WiFi 快照（已冻结）+ 认证客户端 + **Portal 地址（可配置）**。 */
    private fun buildAuthFlow() {
        authFlow = AuthFlow(
            credentials = RepositoryCredentialLookup(SrunStorage.credentialRepository(this)),
            wifiMap = MapWifiAccountLookup(SrunStorage.wifiAccountMap(this)),
            wifiSnapshot = CoreWifiSnapshotPort(
                WifiSnapshotCore(AndroidWifiSource(this), AndroidWifiPermissionFlow(this))
            ),
            transport = SrunAuthClient(),
            // 元素 10：Portal 地址来自持久化配置（用户保存值优先，缺失回落 DEFAULT_PORTAL）。
            // 用「工厂函数」而不是在这里直接调用 SrunStorage.keyValueStore(this)：
            // 取值时机推迟到 AuthFlow.run() 真正调用 portal() 时。以工厂函数（而非 lambda 对象）持有
            // Activity，避免把 this 捕获进闭包（否则会有 Activity 泄漏风险）。
            portalProvider = StoredPortalProvider(AuthFlowFactory.portalStore(this))
        )
    }

    private fun buildViewModel() {
        // portalStore 在此首次访问 → 触发 by lazy 求值；此时 onCreate 已执行，Activity 已 attach
        viewModel = ConfigViewModel(wifiUiPort, loginTrigger, portalStore)
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

        // 元素 10：Portal 地址（读当前配置值填入输入框；保存时持久化到键值存储）
        editPortal.setText(viewModel.state.portalInput)
        editPortal.addTextChangedListener(SimpleTextWatcher { viewModel.setPortal(it) })
        btnSavePortal.setOnClickListener {
            when (val outcome = viewModel.savePortal()) {
                is PortalSaveOutcome.Invalid -> toast(outcome.message)
                is PortalSaveOutcome.Saved -> {
                    // 规范化后的地址回填输入框（避免与已保存值不一致）
                    if (editPortal.text.toString() != outcome.portal) editPortal.setText(outcome.portal)
                    toast(getString(R.string.save_portal_done, outcome.portal))
                }
            }
            render()
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

        /** logcat 过滤标签（排查启动闪退：`adb logcat -s SrunAutoLogin`）。 */
        const val TAG = "SrunAutoLogin"

        /** 启动崩溃落盘文件名（位于应用私有目录 files/）。 */
        const val CRASH_FILE = "crash-startup.txt"
    }
}

/**
 * Portal 存储工厂（**故意的间接层**）。
 *
 * `AuthFlow` 的构造发生在 `onCreate` 的 `buildAuthFlow()` 里，而 `SrunStorage.keyValueStore(context)`
 * 需要 Activity 已 attach。若把 `SrunStorage.keyValueStore(this)` 直接写在 `AuthFlow(...)` 的参数位，
 * 求值时刻与写成实例属性初始化器是一样的风险面（都在 Activity 尚未 attach 或刚 attach 的边缘）。
 * 因此统一走这里：**只有真正调用 `portalStore(activity)` 时才取存储**，且以「函数调用」而非
 * lambda 对象的形式持参（避免闭包捕获 Activity）。离线核对见 artifacts/portal-config1/。
 */
private object AuthFlowFactory {
    fun portalStore(activity: Activity) = SrunStorage.keyValueStore(activity)
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
