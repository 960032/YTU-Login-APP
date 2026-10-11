package top.ytu.srunautologin.ui

import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
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
    private lateinit var scrollRoot: ScrollView
    private lateinit var textPermissionNotice: TextView
    private lateinit var textPermissionState: TextView
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

        // insets-fix1（A：系统栏/刘海/圆角适配）——**必须在 setContentView 之前**：
        // 先声明「窗口内容自己负责避让系统栏」，再把 insets 监听器挂给布局根 scroll_root。
        // 顺序不能反：setDecorFitsSystemWindows(false) 会让 insets 重新下发一次，
        // 监听器必须先就位，才能接住那一次下发。
        applyWindowInsetsBeforeContent()
        setContentView(R.layout.activity_main)

        // 说明（crashfix1 任务 A）：setContentView + 下面这 17 个 findViewById **故意留在 try 之外**。
        // 依据 artifacts/crash-audit1/audit-report.md：布局与 id 已逐个核对匹配，这段调用不依赖权限、
        // 不访问磁盘、不取系统服务，不在「可能抛异常」的清单里；把它们一起包住只会掩盖布局类错误。
        // view-fix1 新增 2 个：scroll_root（滚动根，用于自动滚动）与 text_permission_state（权限状态行）。
        // 它们只在 onCreate 内 findViewById，**不构成实例属性初始化器触碰 Context**（crashfix2 硬约束）。
        scrollRoot = findViewById(R.id.scroll_root)
        editUsername = findViewById(R.id.edit_username)
        editPassword = findViewById(R.id.edit_password)
        spinnerCarrier = findViewById(R.id.spinner_carrier)
        editLabel = findViewById(R.id.edit_label)
        btnUseCurrentWifi = findViewById(R.id.btn_use_current_wifi)
        ssidList = findViewById(R.id.ssid_list)
        textPermissionNotice = findViewById(R.id.text_permission_notice)
        textPermissionState = findViewById(R.id.text_permission_state)
        btnRequestPermission = findViewById(R.id.btn_request_permission)
        btnSave = findViewById(R.id.btn_save)
        textStatus = findViewById(R.id.text_status)
        btnLoginNow = findViewById(R.id.btn_login_now)
        editNewSsid = findViewById(R.id.edit_new_ssid)
        editPortal = findViewById(R.id.edit_portal)
        btnSavePortal = findViewById(R.id.btn_save_portal)

        // insets-fix1（A）：把系统栏 insets 作为 padding 应用到滚动根上。
        // 放在 findViewById 之后、try 之外，与上面 16 行 findViewById 同一性质的「纯绑定」动作
        // （不取系统服务、不读磁盘、不依赖权限），因此不违反 crashfix1 的 try 边界划分。
        applyInsetPaddingToScrollRoot()

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

        // ⑤ 最后一步：接管焦点并回到顶部（真机反馈：界面顶部「密码」以上不可访问）。详见方法 KDoc。
        scrollToTopOnStart(savedInstanceState)
    }

    /**
     * 真机反馈修复（view-fix2）：**阻止子控件自动抢焦点，并让内容回到顶部**。
     *
     * 机制解释（为什么「滑动完全不动」+「『密码』以上不能访问」同时出现）：
     *  1) 布局比屏幕长，只靠 ScrollView 提供滚动。而 ScrollView **本身**可聚焦的前提是
     *     `android:focusableInTouchMode="true"`；此前布局没写 → ScrollView 不在触摸模式焦点链上。
     *     `ViewGroup` 的状态恢复（`dispatchRestoreInstanceState` → `restoreDefaultFocus()`）在
     *     布局完成后会做一次「找不到焦点就自己拿」的查找；ScrollView 拿不了焦点，
     *     这个焦点就落到了**第一个可聚焦子控件** = `edit_username`（账号输入框），
     *     而 EditText 进入触摸模式后停留在「内部编辑器聚焦」状态。
     *  2) 子控件获得焦点时，`ScrollView.requestChildRectangleOnScreen()` 会把该子控件滚动到可见区域，
     *     于是布局刚完成、用户还没碰屏幕，内容就已经被**自动滚下去**了 → 顶部（标题、账号框）被顶出可视区
     *     = 用户原话「『密码』以上部分不能正常访问」。
     *  3) 同一时刻，那个 EditText 在触摸模式下**持续持有焦点**。用户手指在空白处上下滑时，
     *     `ScrollView` 的拖动是先经过 `onInterceptTouchEvent` 判定的：触摸模式下内容视图持有焦点时，
     *     ScrollView 会先把这次手势当作「把焦点交给 ScrollView 自己」的一步，
     *     这一次手势不产生滚动位移 → 在下滑手势里就表现为「完全不动」；用户不会连续滑两次，
     *     于是直观结论就是「滚动完全没响应」。
     *  ⇒ 两个现象同一根因：**焦点错误地被 EditText 抢占**，而不是 ScrollView 缺失（它一直在）。
     *
     * 修法（Android 官方对这类「ScrollView 里的 EditText 抢焦点」的经典处理）：
     *  a) 布局里给 ScrollView 补 `android:focusable="true"` + `android:focusableInTouchMode="true"`
     *     —— 让它具备在触摸模式下持有焦点的资格，不再被跳过；
     *  b) 这里在 onCreate 末尾（此时 setContentView 已完成）调用 `requestFocus()` 主动把焦点拿过来，
     *     而不必再等 `restoreDefaultFocus()` 去猜；
     *  c) `scrollTo(0, 0)` 把第 2) 步可能已经产生的滚动偏移显式复位。
     *
     * 两个保护：
     *  - **必须在 `view.post { }` 里做**：onCreate 此刻只跑完 `setContentView` 的解析，measure/layout 还没做，
     *    直接 `scrollTo(0,0)` 会被随后的布局覆盖，`requestFocus` 也可能因为没有尺寸而失败；
     *    post 把动作排到布局/测量之后的下一帧，滚动位置才落得实。
     *  - **仅在 `savedInstanceState == null` 时执行**：这是冷启动/首次进入配置界面。
     *    屏幕旋转、从后台被杀后重建时 savedInstanceState 非空，此时必须让系统按自己的规则恢复视图状态
     *    （包括用户离开前的滚动位置），强行复位会与系统恢复打架、把用户位置弹回顶部。
     */
    private fun scrollToTopOnStart(savedInstanceState: Bundle?) {
        if (savedInstanceState != null) return
        if (!this::scrollRoot.isInitialized) return
        scrollRoot.post {
            try {
                // 先取焦点：ScrollView 成为触摸模式下的焦点持有者，后续 EditText 不再被自动聚焦
                scrollRoot.requestFocus()
                // 再复位滚动：把「EditText 抢焦点导致的自动下滚」抵消掉，保证顶部（标题/账号框）可见
                scrollRoot.scrollTo(0, 0)
            } catch (t: Throwable) {
                // 焦点/滚动是体验修复，绝不能让它把 onCreate 之后的流程带崩
                Log.e(TAG, "回到顶部与接管焦点失败（已忽略）", t)
            }
        }
    }

    /**
     * insets-fix1（A-1）：声明「窗口不替我们避让系统栏」——**只对 Android 15（API 35）及以上调用**。
     *
     * 背景（问题机制）：`targetSdk = 36`，Android 15 起系统对这类应用**强制 edge-to-edge**：
     * 窗口坐标铺满整块屏幕（y=0 一直到屏幕底部），`android:windowLayoutInDisplayCutoutMode=never`
     * 只保证窗口不铺进挖孔/刘海，**并不会**把内容让开状态栏与导航栏。
     * 于是 `ScrollView` 的第 0 行像素正好落在状态栏（以及屏幕顶部圆角）下面 = 用户报的「内容被压住」。
     *
     * 为什么 `Build.VERSION.SDK_INT < 35` 时**什么都不做**：
     * `setDecorFitsSystemWindows(true)`（API 26–34 的默认值）下，decor 视图**自己**把系统栏空间让开，
     * 内容本来就落在系统栏之下、不会被遮挡。若此时再调 `false`，反而会把内容推进系统栏里；
     * 如果再叠加 insets padding，就成了**双重留白**（顶部空出一整个状态栏高度）。
     * 所以这里的选择是：**只让一套机制负责留白**——
     *   · API 35+：`setDecorFitsSystemWindows(false)` + 下面的 insets padding（框架 insets 方案）；
     *   · API 26–34：**完全交给 decor 默认行为**（等价于 `fitsSystemWindows="true"` 的效果），
     *     既不调 `false`，布局里**也没有**写 `android:fitsSystemWindows="true"` →
     *     同一时刻只有一套机制在留白，不存在重复。
     * 这也是布局里那句 `android:fitsSystemWindows` 至今为空的原因（本任务**故意不补**，见 fix-report.md 第五节）。
     *
     * `Build` 的读取发生在方法体内（`onCreate` 内）：`Build.VERSION.SDK_INT` 是静态字段，
     * 不触碰 Context / 系统服务 / 资源，**不构成实例属性初始化器触碰 Context**（crashfix2 硬约束）。
     */
    private fun applyWindowInsetsBeforeContent() {
        if (Build.VERSION.SDK_INT >= 35) {
            // 框架原生 API：android.view.Window#setDecorFitsSystemWindows，自 API 30 起存在；
            // 这里再加 >= 35 的守卫，是为了让 30–34 保持「decor 负责避让」的既有行为（不改变线上表现）。
            window.setDecorFitsSystemWindows(false)
        }
    }

    /**
     * insets-fix1（A-1）：把 **system bars 的 insets** 作为 padding 应用到 `scroll_root`。
     *
     * 逐行说明「为什么顶部不再被状态栏/屏幕圆角压住」：
     *  1) 只对 API 30+ 处理（[WindowInsets.Type] 是 API 30 引入的）。API 26–29 由 decor 默认行为留白，
     *     所以这里**不做任何事**——这是「二选一」里的选择，不是遗漏。
     *  2) `getInsets(WindowInsets.Type.systemBars())` 一次拿到**状态栏 + 导航栏 + 显示挖孔**合成的安全区：
     *     · top = 状态栏高度（真机 Redmi Turbo 4 Pro 上是含挖孔安全区的那一段）；
     *     · bottom = 导航栏高度（手势条或三键导航都算）；
     *     · left/right = 横屏/侧边刘海时的侧向安全区。
     *  3) 把 top 给 `paddingTop`、bottom 给 `paddingBottom`，等于给滚动区**上边**和**下边**各垫一块
     *     与系统栏等高的空白：内容的第一行像素从 `y = 状态栏高度` 开始画，
     *     不再落在状态栏与顶部圆角那一带 → 顶部内容（标题、账号框）重新可见、可点。
     *  4) **左右 padding 保底 4dp**：滚动条的 `scrollbarStyle=insideInset` 需要那 4dp 空间，
     *     所以写成 `max(4dp, insets.left/right)`，**不是**直接赋 `insets.left`（那会在竖屏把 4dp 覆盖成 0）。
     *  5) `clipToPadding` 布局里是 `false`：滚动时内容可以画进 padding 区域，
     *     所以这块 padding 只是「安全区留白」，不会在滚动中出现硬边。
     *
     * **幂等性**（为什么不会「每回调一次就多加一截」）：
     *  · `setOnApplyWindowInsetsListener` 每次下发都**重新调用**本 lambda，若里面写 `paddingTop += top`
     *    就会随着回调次数（旋转、键盘、系统栏显隐都会触发）不断累加；
     *  · 本实现用的是 `paddingTop = 4dp基准 + 0` / `paddingTop = top` 这种**从常量重新计算**的写法，
     *    即「固定基准 + 当前 inset」，**每算一次都覆盖上一次的结果**，所以对同一个 inset 重复调用 N 次，
     *    结果与调用 1 次完全相同（严格幂等）。
     *  · 同时把「本方法只在 onCreate 里挂一次监听器」也写清：`setOnApplyWindowInsetsListener` 是**替换**语义，
     *    重复调用只会换成新监听器，不会叠加。
     *
     * **return 值**：返回 `insets`（即 dsh 任务里说的「消费后再返回」写法）。`WindowInsets` 是**不可变**对象，
     * 框架对「消费」的判定只看返回对象里的 consumed 标记；直接返回原对象 = 「我不再把这次下发继续传给子控件」，
     * 由本 View 独占处理。这样 padding 只由这一处决定，不会与子控件的 insets 处理重复叠加。
     *
     * 零依赖：`WindowInsets` / `WindowInsets.Type` / `OnApplyWindowInsetsListener` / `ViewGroup.LayoutParams`
     * 全部是框架原生 API，**未引入 androidX.core 的 `ViewCompat.setOnApplyWindowInsetsListener`**。
     */
    private fun applyInsetPaddingToScrollRoot() {
        // 基线的左右 padding（与布局里的 paddingEnd/Right=4dp 一致；该值需与 XML 保持同步）
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
            // 见方法 KDoc：返回同一对象即「本 View 消费掉这次下发」，不再继续下发
            insets
        }
        // 冷启动时先要一次下发：部分机上（尤其真机 HyperOS）insets 不会在挂监听器那一刻自动派发，
        // 主动 requestApplyInsets 是框架文档给出的标准做法，同样零依赖。
        scrollRoot.requestApplyInsets()
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
            // 说明与状态要拆开赋值（见 render）；这里抽出方法，便于在弹窗关闭后再滚动到状态行。
            requestPermissionWithRationale()
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
            // 保存结果同样落在最下方状态区：主动滚过去，让用户立刻看到「成功/失败原因」
            scrollTo(textStatus)
        }

        // 元素 9：立即登录（B8 在 AuthFlow 内判定；SSID 不匹配时零请求）
        btnLoginNow.setOnClickListener {
            viewModel.loginNow()
            render()
            // 结果写在界面最下方；主动滚过去，避免用户以为「点了没反应」
            scrollTo(textStatus)
        }
    }

    /**
     * 元素 6：权限说明 → 申请 → 结果 的完整流程（顺序由 ViewModel 强制，这里只负责展示与触发）。
     *
     * 与改造前的差别只有两点：① 弹窗关闭后主动滚到权限状态行；② 流程本体从点击 lambda 抽成本方法
     * （lambda 内滚动会被 AlertDialog 的窗口遮挡，先关窗再滚更可靠）。顺序、参数、文案一概未动。
     */
    private fun requestPermissionWithRationale() {
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
                scrollTo(textPermissionState)
            }
            .setNegativeButton(R.string.permission_grant_cancel) { _, _ ->
                // 说明阶段被拒：等同拒绝 → 第 4 步 onRequestResult(DENIED) → 降级为只检测当前 WiFi
                viewModel.beginPermissionRequest()
                viewModel.onPermissionResult(false)
                render()
                scrollTo(textPermissionState)
            }
            .show()
    }

    /** 元素 6：权限状态行文案（中文、面向用户、不含内部术语；降级时追加「（降级中）」）。 */
    private fun permissionStateText(s: ConfigUiState): String {
        val granted = s.permissionState == WifiPermissionState.GRANTED
        val base = getString(
            if (granted) R.string.permission_state_granted else R.string.permission_state_denied
        )
        return if (s.degraded) base + getString(R.string.permission_state_degraded_suffix) else base
    }

    /**
     * 元素 6：权限状态行的**颜色**（用户明确要求：未获得=红、获得=绿，且要在代码里按状态设置）。
     *
     * 三态设计：降级（权限被拒但登录当前 WiFi 仍可用）单独给琥珀色，使它既不像「已授权」那样绿，
     * 也不像「完全没授权」那样红——降级是可用的中间态，用户一眼能分清。
     * 颜色常量集中在 companion object，避免同一语义的色值散落多处。
     */
    private fun permissionStateColor(s: ConfigUiState): Int = when {
        s.degraded -> COLOR_PERMISSION_DEGRADED
        s.permissionState == WifiPermissionState.GRANTED -> COLOR_PERMISSION_GRANTED
        else -> COLOR_PERMISSION_DENIED
    }

    /**
     * 滚动到指定控件（内容变化后主动引导视线）。
     *
     * **必须 `post`**：`render()` 改完文本时控件的新高度尚未测量，此刻读 `target.top` 会拿到旧值甚至 0，
     * 滚过去会落空或停在错误位置。`post` 把滚动排到下一帧（测量/布局之后）执行；
     * 视图尚未初始化（如启动兜底路径里 render 早于 findViewById）时直接跳过，绝不抛异常。
     */
    private fun scrollTo(target: View) {
        if (!this::scrollRoot.isInitialized) return
        scrollRoot.post {
            if (target.width == 0 && target.height == 0) return@post
            scrollRoot.smoothScrollTo(0, target.top)
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
        applyStateColor(textStatus, if (s.statusOk) COLOR_STATUS_OK else COLOR_STATUS_FAIL)
        if (s.lastResult != null && !s.statusOk) {
            Toast.makeText(this, s.statusText, Toast.LENGTH_LONG).show()
        }

        // 元素 6 的「状态行」：与说明严格分开（不同 TextView + 中间分隔线），颜色按状态变化：
        // 已获得 = 绿（0xFF2E7D32）、未获得 = 红（0xFFC62828），降级时在文案末尾追加「（降级中）」。
        textPermissionNotice.text = buildString {
            if (s.rationaleShown) append(s.rationaleText).append('\n')
            append(s.noticeText)
        }
        textPermissionState.text = permissionStateText(s)
        // 颜色**由代码按状态设置**（不是 XML 写死单色）：已获得=绿、未获得=红、降级=琥珀。
        // 降级态（权限被拒但仍能登录当前 WiFi）单列一色，避免它被误读成「已授权」或「完全不可用」。
        textPermissionState.setTextColor(permissionStateColor(s))

        ssidList.removeAllViews()
        // insets-fix1（B-2）：周边 WiFi 在权限授予后可能有上百个。全量渲染会让 ssid_list 变得极长，
        // 把下面的权限区/保存/状态区推到很远，用户以为「界面就这些」。
        // 策略：最多渲染 SSID_LIST_MAX_VISIBLE 项，其余只报数量（不丢信息：数字来自同一个 s.ssidList）。
        val visibleSsidList = s.ssidList.take(SSID_LIST_MAX_VISIBLE)
        for (ssid in visibleSsidList) {
            val check = CheckBox(this)
            check.text = ssid
            check.isChecked = ssid == s.selectedSsid
            check.setOnClickListener {
                viewModel.selectSsid(ssid)
                render()
            }
            ssidList.addView(check)
        }
        val hiddenSsidCount = s.ssidList.size - visibleSsidList.size
        if (hiddenSsidCount > 0) {
            // 截断提示：一个普通 TextView（非可勾选），明确告诉用户「还有 N 个没显示」而不是悄悄少给
            val more = TextView(this)
            more.text = getString(R.string.ssid_list_more, hiddenSsidCount)
            ssidList.addView(more)
        }
        if (s.ssidList.isEmpty() && s.degraded) {
            val tv = TextView(this)
            tv.text = getString(R.string.degraded_no_list)
            ssidList.addView(tv)
        }
    }

    /**
     * 给 TextView 上色（文字色 + 选中高亮色一起设）。
     *
     * 为什么同时设 `highlightColor`：TextView 在**文本可选中**或设置了 `autoLink`/`APPEARANCE` 时，
     * 文字选中高亮色默认由主题派生，可能与新的文字色撞色导致文字「看不清」；
     * 代码改色时把 highlight 一并同步成同一色，是零成本的稳妥做法（避免只改一半）。
     * 注意签名：`TextView.highlightColor` 是 `setHighlightColor(int)`（不是 ColorStateList），
     * 故直接传 ARGB 的 Int；写成 `ColorStateList.valueOf(...)` 会编译失败（已被本机编译器抓出）。
     */
    private fun applyStateColor(view: TextView, color: Int) {
        view.setTextColor(color)
        view.highlightColor = color
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
        // 系统弹窗刚关闭，用户最需要看到的就是「到底给没给」→ 滚到权限状态行
        scrollTo(textPermissionState)
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

        /**
         * insets-fix1（B-2）：`ssid_list` 一次最多渲染多少项。
         *
         * 取 20 的理由：手机屏幕高度大约能容纳 20 行 `CheckBox`（每行约 40–48dp），
         * 超过这个数就已经把下方控件推到屏外，再多的「能看见」也没有意义；
         * 20 与「一屏之内」量级一致，不引入任何新依赖或配置项。
         */
        const val SSID_LIST_MAX_VISIBLE = 20

        /**
         * insets-fix1（A-1）：布局里 `ScrollView` 的左右 padding（与 activity_main.xml 的
         * `paddingEnd/Right=4dp` 保持一致，改布局时这里要同步改）。
         * 用途：为 `scrollbarStyle=insideInset` 的滚动条保留空间——加系统栏 insets 时**不能**把它覆盖成 0。
         */
        const val SIDE_PADDING_DP = 4

        /**
         * 元素 6「权限状态行」的三态颜色（用户要求：未获得=红、获得=绿，且由代码按状态设置）。
         *
         * 用 `Int` 常量而不是 `R.color.*`：`getColor(int)` 在 API 26/27 上已废弃（新的
         * `getColor(int, Theme)` 是 API 23+，但为保持一处兼容写法与既有代码风格一致），
         * 直接写 ARGB 最直观；降级态用琥珀色与红/绿区分开。
         */
        const val COLOR_PERMISSION_GRANTED = 0xFF2E7D32.toInt()
        const val COLOR_PERMISSION_DENIED = 0xFFC62828.toInt()
        const val COLOR_PERMISSION_DEGRADED = 0xFFF57F17.toInt()

        /** 元素 8「状态区」颜色：成功=绿、失败=红（与元素 6 复用同两色，语义一致）。 */
        const val COLOR_STATUS_OK = COLOR_PERMISSION_GRANTED
        const val COLOR_STATUS_FAIL = COLOR_PERMISSION_DENIED
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
