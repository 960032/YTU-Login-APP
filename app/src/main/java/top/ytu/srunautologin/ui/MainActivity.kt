package top.ytu.srunautologin.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import top.ytu.srunautologin.R
import top.ytu.srunautologin.auth.HttpUrlConnectionEngine
import top.ytu.srunautologin.auth.SrunAuthClient
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.CoreWifiSnapshotPort
import top.ytu.srunautologin.flow.MapWifiAccountLookup
import top.ytu.srunautologin.flow.ProbeAttemptStore
import top.ytu.srunautologin.flow.RepositoryCredentialLookup
import top.ytu.srunautologin.flow.SrunPortalProbe
import top.ytu.srunautologin.flow.StoredPortalProvider
import top.ytu.srunautologin.work.AutoLoginSwitch
import top.ytu.srunautologin.work.MorningAuthForegroundService
import top.ytu.srunautologin.work.startAutoLoginNotification
import top.ytu.srunautologin.work.stopAutoLoginNotification
import top.ytu.srunautologin.log.AppLog
import top.ytu.srunautologin.log.LogExporter
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.platform.AndroidWifiPermissionFlow
import top.ytu.srunautologin.platform.AndroidWifiSource
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.storage.AccountStore
import top.ytu.srunautologin.storage.SavedAccount
import top.ytu.srunautologin.storage.SecureStoreException
import java.io.File

class MainActivity : Activity() {

    private lateinit var viewModel: ConfigViewModel
    private lateinit var authFlow: AuthFlow
    private var manualLoginThread: Thread? = null

    private lateinit var editUsername: EditText
    private lateinit var editPassword: EditText
    private lateinit var spinnerCarrier: Spinner

    private lateinit var btnToggleAutoLogin: Button
    private lateinit var textAutoLoginStatus: TextView
    private lateinit var editLabel: EditText
    private lateinit var btnUseCurrentWifi: Button
    private lateinit var ssidList: LinearLayout
    private lateinit var scrollRoot: ScrollView
    private lateinit var textPermissionState: TextView
    private lateinit var btnRequestPermission: Button
    private lateinit var btnSave: Button
    private lateinit var textStatus: TextView
    private lateinit var btnLoginNow: Button
    private lateinit var editNewSsid: EditText
    private lateinit var btnLog: Button
    private lateinit var editPortal: EditText
    private lateinit var checkAllowInsecureHttp: android.widget.CheckBox
    private lateinit var btnSavePortal: Button

    private val portalStore by lazy { SrunStorage.keyValueStore(this) }

    private val permissionPort: PermissionPort by lazy {
        object : PermissionPort {
            private val flow = AndroidWifiPermissionFlow(this@MainActivity)

            override val explainText: String get() = flow.explainText

            override fun requiredPermissions(): List<String> = flow.requiredPermissions()

            override fun state(): WifiPermissionState = flow.state()

            override fun markRationaleShown() = flow.markRationaleShown()

            override fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState =
                flow.onRequestResult(outcome)

            override fun capabilityDegradedReason(): String? =
                WifiPermissionPolicy.capability(flow.state()).degradedReason

            override fun requestPermissions() {
                ActivityCompatBridge.request(this@MainActivity, flow.requiredPermissions())
            }
        }
    }

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

    private val loginTrigger: LoginTrigger = object : LoginTrigger {
        override fun login(targetSsid: String?): AuthFlowOutcome = authFlow.run(targetSsid)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        applyWindowInsetsBeforeContent()
        setContentView(R.layout.activity_main)

        scrollRoot = findViewById(R.id.scroll_root)
        editUsername = findViewById(R.id.edit_username)
        editPassword = findViewById(R.id.edit_password)
        spinnerCarrier = findViewById(R.id.spinner_carrier)
        btnToggleAutoLogin = findViewById(R.id.btn_toggle_auto_login)
        textAutoLoginStatus = findViewById(R.id.text_auto_login_status)
        editLabel = findViewById(R.id.edit_label)
        btnUseCurrentWifi = findViewById(R.id.btn_use_current_wifi)
        ssidList = findViewById(R.id.ssid_list)
        textPermissionState = findViewById(R.id.text_permission_state)
        btnRequestPermission = findViewById(R.id.btn_request_permission)
        btnSave = findViewById(R.id.btn_save)
        textStatus = findViewById(R.id.text_status)
        btnLoginNow = findViewById(R.id.btn_login_now)
        editNewSsid = findViewById(R.id.edit_new_ssid)
        editPortal = findViewById(R.id.edit_portal)
        checkAllowInsecureHttp = findViewById(R.id.check_allow_insecure_http)
        btnSavePortal = findViewById(R.id.btn_save_portal)
        btnLog = findViewById(R.id.btn_log)

        applyInsetPaddingToScrollRoot()

        // checkSelfPermission / getSystemService / getScanResults / getConnectionInfo），
        try {
            buildAuthFlow()
            buildViewModel()
            bindViews()
            refreshSsidList()
        } catch (e: Throwable) {
            Log.e(TAG, "启动失败：${e.javaClass.simpleName}")
            writeStartupCrashLog(e)
            if (this::textStatus.isInitialized) {
                val message = "启动失败：" + e.javaClass.simpleName + "：" + "请检查系统权限和存储状态" +
                    "\n详情见 files/" + CRASH_FILE + "（logcat 标签 " + TAG + "）"
                runOnUiThread {
                    try {
                        textStatus.text = message
                    } catch (t: Throwable) {
                        Log.e(TAG, "显示启动失败信息时再次异常（已忽略）", t)
                    }
                }
            }
            return
        }

        scrollToTopOnStart(savedInstanceState)
    }

    private fun scrollToTopOnStart(savedInstanceState: Bundle?) {
        if (savedInstanceState != null) return
        if (!this::scrollRoot.isInitialized) return
        scrollRoot.post {
            try {
                scrollRoot.requestFocus()
                scrollRoot.scrollTo(0, 0)
            } catch (t: Throwable) {
                Log.e(TAG, "回到顶部与接管焦点失败（已忽略）", t)
            }
        }
    }

    private fun applyWindowInsetsBeforeContent() {
        if (Build.VERSION.SDK_INT >= 35) {
            window.setDecorFitsSystemWindows(false)
        }
    }

    private fun applyInsetPaddingToScrollRoot() {
        val baseSidePadding = (SIDE_PADDING_DP * resources.displayMetrics.density).toInt()
        scrollRoot.setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars())
                view.setPadding(
                    maxOf(baseSidePadding, bars.left),
                    bars.top,
                    maxOf(baseSidePadding, bars.right),
                    bars.bottom
                )
            }
            insets
        }
        scrollRoot.requestApplyInsets()
    }

    private fun writeStartupCrashLog(e: Throwable) {
        try {
            val text = buildString {
                append("time=").append(System.currentTimeMillis()).append('\n')
                append("exception=").append(e.javaClass.name).append('\n')
                append("message=hidden for credential protection\n\n")
                append("stack=\n")
                append(e.stackTrace.joinToString("\n") { it.toString() })
            }
            File(filesDir, CRASH_FILE).writeText(text)
        } catch (t: Throwable) {
            Log.e(TAG, "写启动崩溃日志失败（已忽略，不再抛出）", t)
        }
    }

    override fun onResume() {
        super.onResume()
        top.ytu.srunautologin.work.AutoLoginController.onUserVisible(this)
    }

    private fun buildAuthFlow() {
        val app = applicationContext
        authFlow = AuthFlow(
            credentials = RepositoryCredentialLookup(SrunStorage.credentialRepository(app)),
            wifiMap = SrunStorage.accountStore(app),
            enabledAccounts = SrunStorage.accountStore(app),
            wifiSnapshot = CoreWifiSnapshotPort(
                WifiSnapshotCore(AndroidWifiSource(app), AndroidWifiPermissionFlow(app))
            ),
            portalProvider = StoredPortalProvider(AuthFlowFactory.portalStore(this)),
            sessionFactory = top.ytu.srunautologin.platform.AndroidAuthSessionFactory(app, automatic = false)
        ).withProbeAndLog(
            probeGate = top.ytu.srunautologin.flow.ProbePort.inactive,
            probeAttempts = ProbeAttemptStore(portalStore),
            logWriter = { AppLog.record(SrunStorage.keyValueStore(app), it) }
        )
    }

    private fun updatePortalSecurityUi() {
        val http = top.ytu.srunautologin.storage.PortalConfig.normalize(editPortal.text.toString())?.startsWith("http://") == true
        checkAllowInsecureHttp.isEnabled = http
        checkAllowInsecureHttp.isChecked = http && viewModel.state.allowInsecureHttp
    }

    private fun appLog(event: String) {
        try {
            AppLog.record(SrunStorage.keyValueStore(this), event)
        } catch (t: Throwable) {
        }
    }

    private val LOG_RENDER_LIMIT = 400

    private val LOG_DIALOG_MAX_HEIGHT_DP = 360

    private fun buildViewModel() {
        viewModel = ConfigViewModel(wifiUiPort, loginTrigger, portalStore)
        backfillFromStorage()
        spinnerCarrier.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            CarrierOption.displayNames()
        ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
    }

    private fun backfillFromStorage() {
        val restored = runCatching {
            val repo = SrunStorage.credentialRepository(this)
            val all = repo.list()
            val selected = repo.selectedLabel()
            all.firstOrNull { it.label == selected } ?: all.firstOrNull()
        }.getOrNull() ?: return

        runCatching {
            viewModel.selectCarrier(CarrierOption.fromValue(restored.carrier).ordinal)
            if (restored.username.isNotEmpty()) viewModel.setUsername(restored.username)
            if (restored.password.isNotEmpty()) viewModel.setPassword(restored.password)
            if (restored.label.isNotEmpty()) viewModel.setLabel(restored.label)
        }.onFailure { t ->
            Log.e(TAG, "启动回填失败（已降级为默认界面）", t)
        }
    }

    private fun bindViews() {
        editUsername.setText(viewModel.state.usernameInput)
        editPassword.setText(viewModel.state.passwordInput)
        editLabel.setText(viewModel.state.labelInput)

        editUsername.addTextChangedListener(SimpleTextWatcher { viewModel.setUsername(it) })
        editPassword.addTextChangedListener(SimpleTextWatcher { viewModel.setPassword(it) })
        editLabel.addTextChangedListener(SimpleTextWatcher { viewModel.setLabel(it) })
        editNewSsid.addTextChangedListener(SimpleTextWatcher { })

        spinnerCarrier.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
            appLog("用户输入：登录方式选择 position=$position")
                viewModel.selectCarrier(position)
                editLabel.setText(viewModel.state.labelInput)
                render()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }

        btnUseCurrentWifi.setOnClickListener {
            viewModel.useCurrentSsid()
            render()
        }

        btnToggleAutoLogin.setOnClickListener { toggleAutoLoginStatus() }
        renderAutoLoginStatus()

        btnRequestPermission.setOnClickListener {
            requestPermissionWithRationale()
        }

        editPortal.setText(viewModel.state.portalInput)
        editPortal.addTextChangedListener(SimpleTextWatcher {
            viewModel.setPortal(it)
            updatePortalSecurityUi()
        })
        checkAllowInsecureHttp.setOnCheckedChangeListener { _, checked -> viewModel.setAllowInsecureHttp(checked) }
        updatePortalSecurityUi()
        btnSavePortal.setOnClickListener {
            val portalOutcome = viewModel.savePortal()
            if (portalOutcome is PortalSaveOutcome.Invalid) appLog("用户操作：保存门户地址失败（${portalOutcome.message}）")
            when (portalOutcome) {
                is PortalSaveOutcome.Invalid -> toast(portalOutcome.message)
                is PortalSaveOutcome.Saved -> {
                    if (editPortal.text.toString() != portalOutcome.portal) editPortal.setText(portalOutcome.portal)
                    toast(getString(R.string.save_portal_done, portalOutcome.portal))
                    appLog("用户操作：保存门户地址成功（${portalOutcome.portal}）")
                    top.ytu.srunautologin.work.AutoLoginController.onConfigurationChanged(this, "portal-saved")
                }
            }
            render()
        }

        btnSave.setOnClickListener {
            when (val outcome = viewModel.save()) {
                is SaveOutcome.Invalid -> {
                    toast(outcome.message)
                    appLog("用户操作：保存账号/绑定失败（校验未通过：${outcome.message}）")
                }
                is SaveOutcome.Saved -> {
                    savePersistError = null
                    val stored = runCatching {
                        val ssid = outcome.plan.targetSsid
                        val cred = outcome.plan.credential
                        val store = SrunStorage.accountStore(this)
                        val isNew = store.save(
                            ssid = ssid,
                            label = cred.label,
                            username = cred.username,
                            password = cred.password,
                            enabled = null
                        )
                        isNew
                    }
                    if (stored.isFailure) {
                        saveFailed(stored.exceptionOrNull()!!)
                        appLog("用户操作：保存账号/绑定失败（备注「${outcome.plan.label}」，网络「${outcome.plan.targetSsid}」，账号 ${AppLog.maskAccount(outcome.plan.credential.username)}）")
                    } else {
                        toast(getString(R.string.save_done, outcome.plan.label, outcome.plan.targetSsid))
                        appLog("用户操作：保存账号/绑定成功（备注「${outcome.plan.label}」，网络「${outcome.plan.targetSsid}」，账号 ${AppLog.maskAccount(outcome.plan.credential.username)}）")
                        top.ytu.srunautologin.work.AutoLoginController.onConfigurationChanged(this, "account-saved")
                    }
                }
            }
            render()
            scrollTo(textStatus)
        }

        findViewById<Button>(R.id.btn_choose_wifi).setOnClickListener { chooseWifiFromDialog() }

        findViewById<Button>(R.id.btn_choose_account).setOnClickListener { chooseAccountFromDialog() }

        btnLoginNow.setOnClickListener { startLoginNow() }

        btnLog.setOnClickListener { showLogDialog() }
        appLog("应用执行：配置界面已启动（元素 13「日志」按钮可用）")
    }

    private fun showLogDialog() {
        try {
            val refreshIntervalMs = 1000L

            var headerTv: TextView? = null
            var bodyTv: TextView? = null
            var scrollArea: ScrollView? = null

            var dialogShowing: () -> Boolean = { true }

            fun currentLines(): List<String> =
                runCatching { AppLog.list(portalStore) }.getOrDefault(emptyList())

            fun maxScrollY(sv: ScrollView): Int {
                val content = sv.getChildAt(0)?.height ?: 0
                return (content - sv.height).coerceAtLeast(0)
            }

            fun isNearBottom(sv: ScrollView, slackPx: Int): Boolean =
                sv.scrollY >= maxScrollY(sv) - slackPx

            val stickSlackPx = (24 * resources.displayMetrics.density).toInt()

            fun render(): List<String> {
                val all = currentLines()
                val shown = if (all.size > LOG_RENDER_LIMIT) all.subList(all.size - LOG_RENDER_LIMIT, all.size) else all
                val sv = scrollArea
                val body = bodyTv
                val userSelecting = body?.hasSelection() == true

                val headerText = if (all.size > LOG_RENDER_LIMIT) {
                    getString(R.string.log_showing_recent, shown.size, all.size)
                } else {
                    getString(R.string.log_count, all.size)
                }
                val nextHeader = if (userSelecting) headerText + getString(R.string.log_paused_hint) else headerText
                if (headerTv?.text?.toString() != nextHeader) headerTv?.text = nextHeader

                val nextBody = if (shown.isEmpty()) getString(R.string.log_empty) else shown.joinToString("\n")
                if (body != null && !userSelecting && body.text?.toString() != nextBody) {
                    val anchorY = sv?.scrollY ?: 0
                    val stayAtBottom = sv == null || isNearBottom(sv, stickSlackPx)
                    body.text = nextBody
                    if (sv != null) {
                        sv.post {
                            if (!dialogShowing()) return@post
                            val max = maxScrollY(sv)
                            val target = if (stayAtBottom) max else anchorY.coerceIn(0, max)
                            sv.scrollTo(0, target)
                        }
                    }
                }
                return all
            }

            val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            val header = TextView(this).apply {
                setTextColor(LINK_BLUE)
                setPadding(16, 12, 16, 4)
            }
            headerTv = header
            column.addView(header)
            val body = TextView(this).apply {
                textSize = 11f
                typeface = android.graphics.Typeface.MONOSPACE
                setTextColor(Color.DKGRAY)
                setPadding(16, 4, 16, 12)
                setTextIsSelectable(true)
                gravity = Gravity.START
            }
            bodyTv = body
            val scroll = ScrollView(this).apply { addView(body) }
            scrollArea = scroll
            column.addView(scroll, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (LOG_DIALOG_MAX_HEIGHT_DP * resources.displayMetrics.density).toInt()
            ))

            val exportBtn = Button(this).apply {
                text = getString(R.string.log_export)
                setOnClickListener { exportLogs() }
            }
            column.addView(exportBtn, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))

            render()

            val dialog = AlertDialog.Builder(this)
                .setTitle(R.string.log_dialog_title)
                .setView(column)
                .setPositiveButton(R.string.log_copy_all) { _, _ -> copyAllLogs() }
                .setNeutralButton(R.string.log_clear) { _, _ -> confirmClearLogs { render() } }
                .setNegativeButton(R.string.dialog_cancel, null)
                .create()
            dialogShowing = { dialog.isShowing }

            val ticker = object : Runnable {
                override fun run() {
                    if (!dialog.isShowing) return
                    render()
                    scrollArea?.postDelayed(this, refreshIntervalMs)
                }
            }
            dialog.setOnDismissListener { scrollArea?.removeCallbacks(ticker) }

            dialog.show()
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL)?.setOnClickListener {
                confirmClearLogs { render() }
            }
            scrollArea?.postDelayed(ticker, refreshIntervalMs)
        } catch (t: Throwable) {
            Log.e(TAG, "打开日志窗口失败", t)
            toast("打开日志失败：" + t.javaClass.simpleName)
        }
    }

    private fun copyAllLogs() {
        try {
            val all = runCatching { AppLog.list(portalStore) }.getOrDefault(emptyList())
            if (all.isEmpty()) {
                toast(getString(R.string.log_copy_empty))
                return
            }
            val cm = getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager
            if (cm == null) {
                toast(getString(R.string.log_copy_empty))
                return
            }
            cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.log_dialog_title), all.joinToString("\n")))
            toast(getString(R.string.log_copied, all.size))
        } catch (t: Throwable) {
            Log.e(TAG, "复制日志失败", t)
            toast("复制日志失败：" + t.javaClass.simpleName)
        }
    }

    private fun exportLogs() {
        try {
            val all = runCatching { AppLog.list(portalStore) }.getOrDefault(emptyList())
            if (all.isEmpty()) {
                toast(getString(R.string.log_export_empty))
                return
            }
            val snapshot = ArrayList(all)   // 后台线程用；写成独立 list，避免与后续写入并发读同一结构
            val exportedAt = System.currentTimeMillis()
            val versionCode = appVersionCode()
            Toast.makeText(this, getString(R.string.log_exporting), Toast.LENGTH_SHORT).show()
            Thread {
                try {
                    val target = File(
                        getExternalFilesDir(null) ?: File(filesDir, "logs").apply { mkdirs() },
                        LogExporter.fileName(exportedAt)
                    )
                    target.parentFile?.mkdirs()
                    target.writeText(
                        LogExporter.buildMarkdown(snapshot, exportedAt, versionCode),
                        Charsets.UTF_8
                    )
                    runOnUiThread {
                        try {
                            val (dir, name) = LogExporter.displayPath(target.absolutePath)
                            Toast.makeText(
                                this,
                                getString(R.string.log_export_done, snapshot.size, dir, name),
                                Toast.LENGTH_LONG
                            ).show()
                        } catch (t: Throwable) {
                            Log.e(TAG, "导出日志提示失败", t)
                        }
                    }
                } catch (t: Throwable) {
                    Log.e(TAG, "导出日志失败", t)
                    runOnUiThread {
                        try {
                            appLog("导出日志失败：" + t.javaClass.simpleName)
                            toast(getString(R.string.log_export_failed, t.javaClass.simpleName))
                        } catch (t2: Throwable) {
                            Log.e(TAG, "导出失败提示也失败了", t2)
                        }
                    }
                }
            }.start()
        } catch (t: Throwable) {
            Log.e(TAG, "导出日志失败（启动阶段）", t)
            toast(getString(R.string.log_export_failed, t.javaClass.simpleName))
        }
    }

    private fun appVersionCode(): Int = try {
        packageManager.getPackageInfo(packageName, 0).versionCode
    } catch (t: Throwable) {
        0
    }

    private fun confirmClearLogs(afterClear: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(R.string.log_clear_confirm)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val n = runCatching { AppLog.list(portalStore).size }.getOrDefault(0)
                runCatching { AppLog.clear(portalStore) }
                appLog("用户操作：清空日志（原 $n 条）")
                afterClear()
            }
            .setNegativeButton(R.string.dialog_cancel, null)
            .show()
    }

    private fun startLoginNow() {
        if (!btnLoginNow.isEnabled) return
        btnLoginNow.isEnabled = false
        textStatus.text = getString(R.string.login_running)
        applyStateColor(textStatus, COLOR_STATUS_FAIL)
        scrollTo(textStatus)
        appLog("用户操作：点击「立即登录」")

        val submitted = runCatching {
            val worker = Thread {
                val failure: Throwable? = try {
                    viewModel.loginNow()
                    null
                } catch (t: Throwable) {
                    t
                }
                runOnUiThread { finishLogin(failure) }
            }
            worker.name = "srun-login-now"   // 线程名固定：logcat / 线程转储里可辨认
            worker.isDaemon = true           // 不阻止进程退出（与 AuthJobService 的工作线程同一约定）
            manualLoginThread = worker
            worker.start()
        }
        if (submitted.isFailure) {
            finishLogin(submitted.exceptionOrNull() ?: RuntimeException("启动登录线程失败"))
        }
    }

    override fun onDestroy() {
        manualLoginThread?.let { thread ->
            top.ytu.srunautologin.platform.ActiveWifiSessions.cancelThread(thread)
            thread.interrupt()
        }
        manualLoginThread = null
        super.onDestroy()
    }

    private fun finishLogin(failure: Throwable?) {
        if (isDestroyed || isFinishing) return
        manualLoginThread = null
        try {
            if (failure == null) {
                val st = viewModel.state
                val r = st.lastResult
                val alreadyOnline = top.ytu.srunautologin.auth.AuthResultStatus.isAlreadyOnline(r)
                if (st.statusOk || alreadyOnline) top.ytu.srunautologin.work.AuthWorkWiring.resetBackoff(this, clearUserAction = true)
                appLog(
                    when {
                        alreadyOnline ->
                            "用户操作：「立即登录」结果=已在线（无需重复登录）：${st.statusText.take(120)}"
                        st.statusOk ->
                            "用户操作：「立即登录」结果=成功（${st.statusText.take(120)}）"
                        else ->
                            "用户操作：「立即登录」结果=未登录（code=${r?.code ?: "-"}，" +
                                "失败分类=${r?.failure?.displayName ?: "-"}）：${st.statusText.take(120)}"
                    }
                )
                render()
                scrollTo(textStatus)
            } else {
                showLoginFailure(failure)
            }
        } catch (t: Throwable) {
            Log.e(TAG, "登录收尾渲染失败（已忽略，绝不二次崩溃）", t)
        } finally {
            btnLoginNow.isEnabled = true
        }
    }

    private fun showLoginFailure(e: Throwable) {
        val reason = "请检查网络、权限和账号配置；异常详情未记录以保护凭据"
        val text = getString(R.string.login_failed_prefix) + e.javaClass.simpleName + "：" + reason
        Log.e(TAG, text)
        appLog("用户操作：「立即登录」异常（${e.javaClass.simpleName}）：$reason")
        textStatus.text = text
        applyStateColor(textStatus, COLOR_STATUS_FAIL)
        toast(text)
        scrollTo(textStatus)
    }

    private fun chooseWifiFromDialog() {
        appLog("用户操作：打开 WiFi 选择弹窗")
        refreshSsidList()
        val s = viewModel.state
        val items = s.ssidList.toTypedArray()
        if (items.isEmpty()) {
            val reason = if (s.degraded) {
                getString(R.string.degraded_no_list)
            } else {
                getString(R.string.ssid_list_empty_no_data)
            }
            AlertDialog.Builder(this)
                .setTitle(R.string.dialog_wifi_title)
                .setMessage(reason)
                .setPositiveButton(R.string.dialog_cancel, null)
                .show()
            return
        }
        val checked = s.selectedSsid?.let { sel -> items.indexOfFirst { it == sel } } ?: -1
        AlertDialog.Builder(this)
            .setTitle(R.string.dialog_wifi_title)
            .setSingleChoiceItems(items, checked) { dialog, which ->
                appLog("用户操作：WiFi 选择弹窗中选择「${items[which]}」")
                viewModel.selectSsid(items[which])
                dialog.dismiss()
                render()
                scrollTo(ssidList)
            }
            .setNegativeButton(R.string.dialog_cancel, null)
            .show()
    }

    private fun chooseAccountFromDialog() {
        val store = SrunStorage.accountStore(this)
        appLog("用户操作：打开账号选择弹窗")

        var activeDialog: AlertDialog? = null
        lateinit var renderInto: () -> Unit

        fun showAccountDialog(next: AlertDialog) {
            val old = activeDialog
            activeDialog = next
            old?.dismiss()
            next.show()
        }

        fun showEmptyDialog() {
            showAccountDialog(AlertDialog.Builder(this)
                .setTitle(R.string.dialog_account_title)
                .setMessage(R.string.account_empty)
                .setPositiveButton(R.string.dialog_cancel, null)
                .create())
        }

        fun buildListDialog(current: List<SavedAccount>): AlertDialog {
            val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            val counter = TextView(this).apply {
                text = getString(R.string.account_selected_count, current.count { it.enabled })
                setPadding(12, 8, 12, 8)
                setTextColor(LINK_BLUE)
            }
            column.addView(counter)
            current.forEach { account -> column.addView(buildAccountRow(store, account) { renderInto() }) }
            return AlertDialog.Builder(this)
                .setTitle(R.string.dialog_account_title)
                .setNegativeButton(R.string.dialog_cancel, null)
                .setView(column)
                .create()
        }

        renderInto = {
            val current = runCatching { store.list() }.getOrElse {
                saveFailed(it)
                emptyList()
            }
            if (current.isEmpty()) showEmptyDialog() else showAccountDialog(buildListDialog(current))
        }

        val accounts = runCatching { store.list() }.getOrElse {
            saveFailed(it)
            emptyList()
        }
        if (accounts.isEmpty()) {
            showEmptyDialog()
            return
        }
        showAccountDialog(buildListDialog(accounts))
    }

    private fun buildAccountRow(store: AccountStore, account: SavedAccount, afterChange: () -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(8, 8, 8, 8)
        }
        val checkbox = CheckBox(this).apply {
            isChecked = account.enabled
            tag = "rendering"     // 渲染态标记：setChecked 不触发「写存储」那条分支
        }
        checkbox.setOnCheckedChangeListener { _, checked ->
            if (checkbox.tag == "rendering") return@setOnCheckedChangeListener
            val ok = runCatching { store.setEnabled(account.ssid, checked) }.getOrElse {
                saveFailed(it)
                false
            }
            if (!ok) checkbox.isChecked = account.enabled
            appLog(
                "用户操作：${if (checked) "勾选" else "取消勾选"}账号「${account.label}」（网络「${account.ssid}」）" +
                    if (ok) "" else "——写入失败，已回滚显示"
            )
            if (ok) top.ytu.srunautologin.work.AutoLoginController.onConfigurationChanged(this, "account-toggled")
            afterChange()
        }
        row.addView(checkbox)

        row.addView(TextView(this).apply {
            text = account.label
            textSize = 16f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })

        row.addView(TextView(this).apply {
            text = account.ssid
            textSize = 14f
            setPadding(8, 0, 8, 0)
        })

        row.addView(TextView(this).apply {
            text = getString(R.string.account_delete)
            textSize = 15f
            setTextColor(LINK_BLUE)
            setPadding(8, 4, 4, 4)
            isClickable = true
            setOnClickListener { confirmDeleteAccount(store, account, afterChange) }
        })
        return row
    }

    private fun confirmDeleteAccount(store: AccountStore, account: SavedAccount, afterChange: () -> Unit) {
        AlertDialog.Builder(this)
            .setMessage(getString(R.string.account_delete_confirm, account.label, account.ssid))
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val deleted = runCatching { store.delete(account.ssid, account.label) }.getOrElse {
                    saveFailed(it)
                    false
                }
                if (!deleted) return@setPositiveButton
                appLog("用户操作：删除账号「${account.label}」（网络「${account.ssid}」）")
                runCatching {
                    val repo = SrunStorage.credentialRepository(this)
                    val label = repo.selectedLabel()
                    if (label != null && store.findByName(label) == null) repo.delete(label)
                }
                top.ytu.srunautologin.work.AutoLoginController.onConfigurationChanged(this, "account-deleted")
                afterChange()
                toast(getString(R.string.account_delete_done, account.label, account.ssid))
            }
            .setNegativeButton(R.string.dialog_cancel, null)
            .show()
    }

    private fun renderPortalStatus() {
        val status: TextView = findViewById(R.id.text_portal_status)
        val portalKey = top.ytu.srunautologin.storage.PortalConfig.KEY_PORTAL
        val savedHost = runCatching { portalStore.getString(portalKey) }.getOrNull()
        if (savedHost.isNullOrBlank()) {
            status.text = getString(R.string.portal_status_unsaved)
            applyStateColor(status, COLOR_STATUS_FAIL)   // 红 0xFFC62828
        } else {
            status.text = getString(R.string.portal_status_saved, savedHost)
            applyStateColor(status, COLOR_STATUS_OK)     // 绿 0xFF2E7D32
        }
    }

    private fun requestPermissionWithRationale() {
        appLog("用户操作：点击申请 WiFi/位置信息 权限（先展示用途说明）")
        AlertDialog.Builder(this)
            .setTitle(R.string.permission_explain_title)
            .setMessage(viewModel.permissionExplanation())
            .setPositiveButton(R.string.permission_grant_ok) { _, _ ->
                viewModel.beginPermissionRequest()
                val required = permissionPort.requiredPermissions()
                if (required.isEmpty()) {
                    viewModel.onPermissionResult(true)
                    appLog("用户操作：同意权限说明（当前系统无需运行时权限，直接按已授予处理）")
                } else {
                    appLog("用户操作：同意权限说明 → 弹出系统权限对话框（${required.joinToString(",")}）")
                    permissionPort.requestPermissions()
                }
                render()
                scrollTo(textPermissionState)
            }
            .setNegativeButton(R.string.permission_grant_cancel) { _, _ ->
                viewModel.beginPermissionRequest()
                viewModel.onPermissionResult(false)
                appLog("用户操作：拒绝权限说明（未授权,仅访问当前网络）")
                render()
                scrollTo(textPermissionState)
            }
            .show()
    }

    private fun permissionStateText(s: ConfigUiState): String {
        val granted = s.permissionState == WifiPermissionState.GRANTED
        val base = getString(
            if (granted) R.string.permission_state_granted else R.string.permission_state_denied
        )
        return if (s.degraded) base + getString(R.string.permission_state_degraded_suffix) else base
    }

    private fun permissionStateColor(s: ConfigUiState): Int = when {
        s.degraded -> COLOR_PERMISSION_DEGRADED
        s.permissionState == WifiPermissionState.GRANTED -> COLOR_PERMISSION_GRANTED
        else -> COLOR_PERMISSION_DENIED
    }

    private fun scrollTo(target: View) {
        if (!this::scrollRoot.isInitialized) return
        scrollRoot.post {
            if (target.width == 0 && target.height == 0) return@post
            scrollRoot.smoothScrollTo(0, target.top)
        }
    }

    private fun refreshSsidList() {
        viewModel.refreshSsidList()
        render()
    }

    private fun render() {
        val s = viewModel.state
        val persistError = savePersistError
        if (persistError != null) {
            textStatus.text = persistError
            applyStateColor(textStatus, COLOR_STATUS_FAIL)
        } else {
            textStatus.text = s.statusText
            applyStateColor(textStatus, if (s.statusOk) COLOR_STATUS_OK else COLOR_STATUS_FAIL)
        }
        applyStateColor(textStatus, if (s.statusOk) COLOR_STATUS_OK else COLOR_STATUS_FAIL)
        if (s.lastResult != null && !s.statusOk) {
            Toast.makeText(this, s.statusText, Toast.LENGTH_LONG).show()
        }

        textPermissionState.text = permissionStateText(s)
        textPermissionState.setTextColor(permissionStateColor(s))

        ssidList.removeAllViews()
        val selectedLine = TextView(this)
        selectedLine.text = if (s.selectedSsid.isNullOrBlank()) {
            getString(R.string.ssid_selected_none)
        } else {
            getString(R.string.ssid_selected_current, s.selectedSsid)
        }
        ssidList.addView(selectedLine)
        if (s.ssidList.isNotEmpty()) {
            val countLine = TextView(this)
            countLine.text = getString(R.string.ssid_list_count, s.ssidList.size)
            ssidList.addView(countLine)
        }
        if (s.ssidList.isEmpty() && s.degraded) {
            val tv = TextView(this)
            tv.text = getString(R.string.degraded_no_list)
            ssidList.addView(tv)
        } else if (s.ssidList.isEmpty() && s.capability.canScanList && s.currentSsid == null) {
            val tv = TextView(this)
            tv.text = getString(R.string.ssid_list_empty_no_data)
            tv.setTextColor(0xFFF57F17.toInt())
            ssidList.addView(tv)
        }

        renderPortalStatus()

        renderAutoLoginStatus()

        syncForegroundNotificationWithSwitch()
    }

    private fun toggleAutoLoginStatus() {
        try {
            val kv = SrunStorage.keyValueStore(this)
            val current = AutoLoginSwitch.isEnabled(kv)
            val next = !current
            val actual = top.ytu.srunautologin.work.AutoLoginController.setEnabled(this, next)

            appLog("用户操作：切换自动登录开关 → ${if (actual) "启用" else "停用"}")

            if (actual) {
                if (MorningAuthForegroundService.notificationPermissionGranted(this)) {
                    startForegroundServiceIfEnabled()
                } else {
                    requestNotificationPermissionIfNeeded()
                }
            } else {
                stopForegroundNotification(reason = "用户停用开关")
            }

            renderAutoLoginStatus()
            toast(getString(if (actual) R.string.auto_login_status_enabled else R.string.auto_login_status_disabled))
        } catch (t: Throwable) {
            Log.e(TAG, "切换自动登录开关失败（已忽略异常）", t)
            appLog("用户操作：切换自动登录开关失败（${t.javaClass.simpleName}）")
            runCatching { renderAutoLoginStatus() }
        }
    }

    private fun renderAutoLoginStatus() {
        if (!this::textAutoLoginStatus.isInitialized) return
        val enabled = runCatching { AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(this)) }
            .getOrDefault(AutoLoginSwitch.DEFAULT_ENABLED)
        textAutoLoginStatus.text =
            getString(if (enabled) R.string.auto_login_status_enabled else R.string.auto_login_status_disabled)
        applyStateColor(textAutoLoginStatus, if (enabled) COLOR_STATUS_OK else COLOR_STATUS_FAIL)
    }

    private fun syncForegroundNotificationWithSwitch() {
        top.ytu.srunautologin.work.AutoLoginController.onUserVisible(this)
    }

    private fun startForegroundServiceIfEnabled() {
        top.ytu.srunautologin.work.AutoLoginController.onUserVisible(this)
    }

    private fun stopForegroundNotification(reason: String) {
        appLog("应用执行：停止常驻通知（$reason）")
        stopAutoLoginNotification()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (MorningAuthForegroundService.notificationPermissionGranted(this)) {
            startForegroundServiceIfEnabled()
            return
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                appLog("用户操作：申请通知权限（用于显示常驻通知）")
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATION)
            } else {
                startForegroundServiceIfEnabled()
            }
        } catch (t: Throwable) {
            Log.e(TAG, "申请通知权限失败（已忽略）", t)
            toast(getString(R.string.auto_login_toast_notification_denied))
        }
    }

    private fun applyStateColor(view: TextView, color: Int) {
        view.setTextColor(color)
        view.highlightColor = color
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIFICATION) {
            val granted = grantResults.isNotEmpty() &&
                grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            appLog("用户操作：通知权限 ${if (granted) "已授予" else "被拒绝"}")
            if (granted) {
                startForegroundServiceIfEnabled()
            } else {
                toast(getString(R.string.auto_login_toast_notification_denied))
            }
            return
        }
        if (requestCode != REQ_WIFI) return
        val granted = AndroidWifiPermissionFlow(this).state() != WifiPermissionState.DENIED
        appLog("用户操作：WiFi/位置信息 权限 ${if (granted) "已授予" else "被拒绝（降级为只检测当前 WiFi）"}")
        viewModel.onPermissionResult(granted)
        top.ytu.srunautologin.work.AutoLoginController.onConfigurationChanged(this, "wifi-permission-changed")
        top.ytu.srunautologin.work.AutoLoginController.onUserVisible(this)
        render()
        scrollTo(textPermissionState)
    }

    private var savePersistError: String? = null

    private fun saveFailed(e: Throwable) {
        appLog("应用执行：保存失败（${e.javaClass.simpleName}），已保留原有数据")
        val reason = if (e is SecureStoreException) "加密凭据无法读取或保存，已保留原有数据，请勿清除应用数据"
            else "设置未能保存，请重试"
        Log.e("SrunAutoLogin", reason)

        val text = "保存失败：$reason"
        savePersistError = text
        toast(text)
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private companion object {
        const val REQ_WIFI = 1001
        const val REQ_NOTIFICATION = 1002

        const val TAG = "SrunAutoLogin"

        const val CRASH_FILE = "crash-startup.txt"

        const val SSID_LIST_MAX_VISIBLE = 20

        private val LINK_BLUE = 0xFF1976D2.toInt()

        const val SIDE_PADDING_DP = 4

        const val COLOR_PERMISSION_GRANTED = 0xFF2E7D32.toInt()
        const val COLOR_PERMISSION_DENIED = 0xFFC62828.toInt()
        const val COLOR_PERMISSION_DEGRADED = 0xFFF57F17.toInt()

        const val COLOR_STATUS_OK = COLOR_PERMISSION_GRANTED
        const val COLOR_STATUS_FAIL = COLOR_PERMISSION_DENIED
    }
}

private object AuthFlowFactory {
    fun portalStore(activity: Activity) = SrunStorage.keyValueStore(activity)
}

private class SimpleTextWatcher(private val onChanged: (String) -> Unit) :
    android.text.TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
    override fun afterTextChanged(s: android.text.Editable?) = onChanged(s?.toString().orEmpty())
}

private object ActivityCompatBridge {
    fun request(activity: Activity, permissions: List<String>) {
        if (permissions.isEmpty()) return
        activity.requestPermissions(permissions.toTypedArray(), 1001)
    }
}
