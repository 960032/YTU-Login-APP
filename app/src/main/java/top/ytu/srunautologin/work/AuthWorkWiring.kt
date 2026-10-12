package top.ytu.srunautologin.work

import android.content.Context
import top.ytu.srunautologin.auth.HttpUrlConnectionEngine
import top.ytu.srunautologin.auth.SocketLocalIpProbe
import top.ytu.srunautologin.auth.SrunAuthClient
import top.ytu.srunautologin.auth.AuthTransport
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.CoreWifiSnapshotPort
import top.ytu.srunautologin.flow.MapWifiAccountLookup
import top.ytu.srunautologin.flow.PortalProvider
import top.ytu.srunautologin.flow.StoredPortalProvider
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.platform.AndroidWifiPermissionFlow
import top.ytu.srunautologin.platform.AndroidWifiSource
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.platform.WifiSnapshot
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.storage.CredentialRepository

/**
 * ============================ 真机装配层（未验证部分）============================
 * 引用 Android SDK（Context / WifiManager），本机无 Android SDK 无法离线编译。
 *
 * 本文件**只做接线**：把已冻结的 storage / net / auth / flow 模块拼成一次后台认证运行。
 * 不含任何判定逻辑（不判 SSID、不判退避、不判成功）——那些都在纯 JVM 的 work 包与 flow 包。
 * ==============================================================================
 */

/** [CredentialLookup] 的真机实现（与 flow.RepositoryCredentialLookup 语义相同，仅多一个 list）。 */
class StorageCredentialLookup(private val repo: CredentialRepository) : top.ytu.srunautologin.flow.CredentialLookup {
    override fun find(label: String): Credential? = repo.find(label)
    override fun selected(): Credential? = repo.selected()
    fun list(): List<Credential> = repo.list()
}

/**
 * 认证客户端工厂（真机）：`SrunAuthClient(HttpUrlConnectionEngine, SocketLocalIpProbe)`。
 * 与前台「立即登录」共用同一套实现，保证前后台协议行为完全一致。
 */
object AndroidAuthTransportFactory : top.ytu.srunautologin.flow.AuthTransportFactory {
    override fun create(): AuthTransport = SrunAuthClient(
        engine = HttpUrlConnectionEngine(),
        ipProbe = SocketLocalIpProbe()
    )
}

/** Portal 地址回落到代码默认值 [AuthFlow.DEFAULT_PORTAL]（不重复写字面量；真机用下面的工厂）。 */
object DefaultPortalProvider : PortalProvider {
    override fun portal(): String = AuthFlow.DEFAULT_PORTAL
}

/**
 * Portal 地址的**真机实现**：从与界面同一份键值存储读取（用户保存值优先，缺失回落默认值）。
 *
 * 每次装配 [AndroidAuthRunEnv] 时现取一次 → 用户在配置界面改完 Portal 地址后，
 * **下一次后台自动认证立刻使用新地址**，无需等重启（与前台「立即登录」走的 `StoredPortalProvider` 同一份实现）。
 * `context` 必须是 **applicationContext**（避免持有 Activity）；它只在此函数被调用时使用一次，
 * 函数返回后即被丢弃，因此不产生 Context 泄漏。
 */
fun portalProviderFrom(context: Context): PortalProvider =
    StoredPortalProvider(SrunStorage.keyValueStore(context.applicationContext))

/**
 * [AuthRunEnv] 的真机实现：用 Context 装配一次认证运行。
 *
 * @param minRetryIntervalSeconds 周期任务去抖间隔（秒）
 */
class AndroidAuthRunEnv(
    context: Context,
    private val minRetryIntervalSeconds: Long
) : AuthRunEnv {

    private val appContext = context.applicationContext
    private val credentials = StorageCredentialLookup(SrunStorage.credentialRepository(appContext))
    private val wifiMap = SrunStorage.wifiAccountMap(appContext)
    private val wifiSnapshot = WifiSnapshotCore(AndroidWifiSource(appContext), AndroidWifiPermissionFlow(appContext))

    override fun currentSsid(): String? = wifiSnapshot.currentSsid()

    override fun buildRun(trigger: TriggerKind, minRetryIntervalSeconds: Long): AuthRun {
        val flow = AuthFlow(
            credentials = credentials,
            wifiMap = MapWifiAccountLookup(wifiMap),
            wifiSnapshot = CoreWifiSnapshotPort(wifiSnapshot),
            transport = AndroidAuthTransportFactory.create(),
            portalProvider = portalProviderFrom(appContext)
        )
        val coordinator = AuthWorkCoordinator(
            flow = flow,
            store = AuthStatusStore(SrunStorage.keyValueStore(appContext)),
            scheduler = BackoffScheduler(),
            trigger = trigger,
            minRetryIntervalSeconds = if (minRetryIntervalSeconds > 0L) minRetryIntervalSeconds else this.minRetryIntervalSeconds
        )
        // 目标 SSID 的「选择」在 AuthFlowRunner.targetOf 里完成（只读用户绑定集合，不做匹配判定）
        return AuthRun(coordinator, AuthFlowRunner.readCurrentSsid(this))
    }

    /** 用户已绑定的 SSID 集合（只读；为空表示用户还没在界面上保存过账号）。 */
    fun boundSsids(): List<String> = wifiMap.mapping().keys.toList()

    /** 是否存在任何账号凭据（纯判断，不读密码内容）。 */
    fun hasCredential(): Boolean = credentials.list().isNotEmpty()
}

/**
 * 后台认证的装配入口（单例）。
 *
 * 关键约定：
 *  - **永远共用同一个 [SharedPreferencesKeyValueStore] 实例**（同一份 SharedPreferences），
 *    保证 [AuthStatusStore] 写进去的键（B5）与界面读到的是同一份数据；
 *  - 使用 applicationContext，避免持有 Activity 造成泄漏；
 *  - 所有 Android API 调用都用 try/catch 包住，权限被收紧时降级为「不排期」，绝不崩溃。
 */
object AuthWorkWiring {

    private const val PROGRESS_KEY = "srun_auth_progress_v1"
    private const val MAX_PROGRESS_CHARS = 4000

    /** 周期保底间隔（分钟 → Long，避免 Int/Long 混算）。 */
    private val periodicIntervalMinutes: Long = AuthJobs.PERIODIC_INTERVAL_MINUTES.toLong()

    /** 周期任务去抖间隔（秒）。 */
    fun periodicDebounceSeconds(): Long = AndroidAuthScheduler.minRetryIntervalSecondsFor(periodicIntervalMinutes)

    private fun kv(context: Context) = SrunStorage.keyValueStore(context.applicationContext)

    fun keyValueStore(context: Context) = kv(context)

    fun progressRecorder(context: Context) = AuthStatusStore(kv(context))

    fun scheduler(context: Context) = AndroidAuthScheduler(context.applicationContext)

    fun retryPolicy(context: Context): RetryPolicy = BackoffScheduler().policy

    fun maxAttempts(context: Context): Int = retryPolicy(context).maxAttempts

    fun resetBackoff(context: Context) {
        val store = AuthStatusStore(kv(context))
        store.clearAttempts(seq = store.loadAttemptState().seq)
    }

    /** 追加一行进度（保留末尾，最多 [MAX_PROGRESS_CHARS] 字符；真机排障用）。 */
    fun progress(context: Context, line: String) {
        try {
            val store = kv(context)
            val prev = store.getString(PROGRESS_KEY).orEmpty()
            val stamp = AuthStatusStore.formatTime(System.currentTimeMillis())
            val next = prev + "[$stamp] $line\n"
            store.putString(
                PROGRESS_KEY,
                if (next.length > MAX_PROGRESS_CHARS) next.substring(next.length - MAX_PROGRESS_CHARS) else next
            )
        } catch (e: Throwable) {
            // 进度记录失败不影响认证本身
        }
    }

    /** 读回进度（界面/报告用）。 */
    fun progressLog(context: Context): String = kv(context).getString(PROGRESS_KEY).orEmpty()

    /**
     * 跑一次后台认证（**唯一执行入口**）。
     *
     * @param periodic true = 周期保底触发（会按最小间隔去抖，避免周期任务比退避更频繁地打 Portal）
     * @param targetOverride 非 null 时强制使用该目标 SSID（前台「立即登录」用）
     */
    fun run(
        context: Context,
        trigger: TriggerKind,
        periodic: Boolean = false,
        targetOverride: String? = null
    ): AuthRunResult {
        val appContext = context.applicationContext
        val env = AndroidAuthRunEnv(appContext, periodicDebounceSeconds())
        val at = System.currentTimeMillis()

        // ---- 快速返回 0：WiFi 权限被拒/未授予 → 读不到 SSID，**终态**处理 ----
        // 若在这里退回 E_SKIP_NO_SSID，会变成「每 30 秒空转一次」的常驻唤醒（读不到 SSID 永远成立）。
        // 正确做法：写一条可读状态并停止本次重试，等用户下次打开应用补授权。
        val capability = WifiSnapshot.capability(appContext)
        if (capability.degraded) {
            val r = AuthRunResult(
                outcome = RunOutcome.NO_PERMISSION,
                code = "E_NO_WIFI_PERMISSION",
                message = "缺少读取 WiFi 的权限，无法在后台识别当前网络：${capability.degradedReason ?: "原因未提供"}",
                authOk = false,
                trigger = trigger,
                attempt = 0,
                attemptsConsumed = false,
                finishedAtMillis = at,
                delaySeconds = 0L,
                ranFlow = false,
                statusLine = AuthStatusStore.formatLine(
                    trigger = trigger,
                    atMillis = at,
                    ok = false,
                    code = "E_NO_WIFI_PERMISSION",
                    message = "缺少读取 WiFi 的权限，后台自动认证暂不可用（请打开应用授权后重试）",
                    failureName = "权限缺失",
                    attempts = 0,
                    maxAttempts = maxAttempts(appContext)
                )
            )
            AuthStatusStore(kv(appContext)).saveResult(r.statusLine, r.code, false, r.finishedAtMillis)
            progress(appContext, "permission-blocked: ${capability.degradedReason}")
            return r
        }

        // 未配置任何账号 → 不触碰网络，写一条可读状态（不算失败、不消耗退避次数）
        if (!env.hasCredential() && targetOverride == null) {
            val r = AuthFlowRunner.noCredentialResult(trigger, at, maxAttempts(appContext))
            AuthStatusStore(kv(appContext)).saveResult(r.statusLine, r.code, false, r.finishedAtMillis)
            return r
        }

        val bound = env.boundSsids()
        val minInterval = if (periodic) periodicDebounceSeconds() else 0L
        val currentSsid = env.currentSsid()
        val run = env.buildRun(trigger, minInterval)
        // 目标 SSID 的「选择」全部在 AuthFlowRunner.targetOf 里（纯 JVM 可离线验证）
        val target = targetOverride?.trim()?.takeIf { it.isNotEmpty() }
            ?: AuthFlowRunner.targetOf(currentSsid, configuredTarget = null, boundSsids = bound)
        return run.coordinator.run(target)
    }

    /** 开机/网络恢复后调用：注册周期保底并排一次尽快认证。 */
    fun onTrigger(context: Context, reason: String, initialDelayMillis: Long) {
        val appContext = context.applicationContext
        // 【C4 覆盖检查：入口 2/7】boot / app-start / network 三条通道共用本入口。
        // 停用时**直接返回**：不注册周期保底、不排认证任务（用户要求「用户启用后才执行后台任务」）。
        if (!MorningAuthRuntime.isEnabled(appContext)) {
            progress(appContext, "onTrigger($reason)：自动登录已停用 → 直接返回（不排期）")
            return
        }
        try {
            scheduler(appContext).ensurePeriodic()
            scheduler(appContext).enqueueAuthReplacing(initialDelayMillis, reason)
        } catch (e: Throwable) {
            progress(appContext, "onTrigger($reason) 失败：${e.javaClass.simpleName}")
        }
    }
}
