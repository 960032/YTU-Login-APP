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
import top.ytu.srunautologin.flow.ProbeAttemptStore
import top.ytu.srunautologin.flow.StoredPortalProvider
import top.ytu.srunautologin.log.AppLog
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

/**
 * 【logfix1 任务 C 段】探测端口装配：`SrunPortalProbe` = 一次 `get_challenge` GET + [SrunProbeClassifier] 判定。
 *
 * 复用既有 `HttpUrlConnectionEngine`（与认证同一套超时/重定向/UA 行为），不新写任何 HTTP 代码；
 * **网络请求发生在调用它的线程上** → 本函数只在 worker 线程链路里被使用（JobService / 闹钟后台线程 /
 * 「立即登录」的后台线程），满足「探测必须在后台线程」这条硬约束。
 */
fun androidProbeGate(): top.ytu.srunautologin.flow.ProbePort =
    top.ytu.srunautologin.flow.SrunPortalProbe(HttpUrlConnectionEngine())

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
    /**
     * 【accountsel1 任务 C 段】v2 账号列表（含勾选状态）：早上链路里「账号是否生效」以它为准。
     * 读它会触发一次 v1 → v2 迁移（幂等），因此升级后第一次跑早上任务时老账号也已在 v2 里。
     */
    private val accountStore = SrunStorage.accountStore(appContext)
    private val wifiSnapshot = WifiSnapshotCore(AndroidWifiSource(appContext), AndroidWifiPermissionFlow(appContext))

    override fun currentSsid(): String? = wifiSnapshot.currentSsid()

    override fun buildRun(trigger: TriggerKind, minRetryIntervalSeconds: Long): AuthRun {
        val flow = AuthFlow(
            credentials = credentials,
            wifiMap = MapWifiAccountLookup(wifiMap),
            // 【C 段】把「已勾选」判定接进认证链路：未勾选的账号 ⇒ AuthFlow 直接跳过（不发请求）
            enabledAccounts = accountStore,
            wifiSnapshot = CoreWifiSnapshotPort(wifiSnapshot),
            transport = AndroidAuthTransportFactory.create(),
            portalProvider = portalProviderFrom(appContext)
        // 【logfix1 任务 C/B 段：构造后注入】构造签名**逐字冻结**（既有离线核对快照按合成默认构造调用），
        // 因此探测端口与日志 Context 一律在构造完成后装配：
        //  - probeGate：第 ②③ 段判断（SRun 验证 + 是否已登录），一次探测同时得到两个答案；
        //  - probeAttempts：探测重试计数（键 srun_probe_attempt_v1，与认证/早上计数不同的键）；
        //  - logContext：把 SSID 读取/匹配、SRun 判定、登录开始与结果写进应用内日志。
        ).withProbeAndLog(
            probeGate = androidProbeGate(),
            probeAttempts = ProbeAttemptStore(SrunStorage.keyValueStore(appContext)),
            logContext = appContext
        )
        val coordinator = AuthWorkCoordinator(
            flow = flow,
            store = AuthStatusStore(SrunStorage.keyValueStore(appContext)),
            scheduler = BackoffScheduler(),
            trigger = trigger,
            // 【debouncefix1】按调用方传入的值原样传递，**不做 0 回落**：
            // 非周期触发（网络变化/开机/手动）由 AuthFlowRunner.kt:61 明确传 0L，语义是「不限制 / 无去抖」；
            // 周期触发由本文件 :291/:293 显式传 periodicDebounceSeconds()（=450s），周期去抖不受影响。
            // 修掉的旧写法：`if (minRetryIntervalSeconds > 0L) minRetryIntervalSeconds else this.minRetryIntervalSeconds`
            // ——它把非周期的 0 回落成周期去抖值 450s，使网络变化在 450s 内只返回 E_WAIT、连探测都不跑。
            minRetryIntervalSeconds = minRetryIntervalSeconds,
        )
        // 【logfix1 任务 B 段：构造后注入】构造签名逐字冻结（快照按合成默认构造调用），日志缝构造后设置：
        // work 层纯逻辑文件不得 import android（既有离线核对 W42），因此这里传的是「写一行日志」的闭包。
        coordinator.log = { line -> AppLog.record(SrunStorage.keyValueStore(appContext), line) }
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
        val logStore = SrunStorage.keyValueStore(appContext)

        // ---- 【logfix1 任务 C 段】探测重试闸门（周期任务两选一） ----
        // 周期保底每 15 分钟醒一次，而探测重试间隔是 5 分钟 → 周期任务自然能覆盖「5 分钟后再探」，
        // 不需要额外排闹钟（排了也不会更准，Doze 下同样会被推迟）。
        // 手动触发（periodic=false）时**跳过闸门并复位计数**：用户显式点了「立即登录」，
        // 必须立刻真测一次，而不是被上一轮的不确定状态挡在门外。
        val gateSsid = targetOverride?.trim()?.takeIf { it.isNotEmpty() } ?: env.currentSsid()
        if (periodic) {
            when (
                ProbeRetryCoordinator.beforeProbe(
                    kv = logStore,
                    ssid = gateSsid,
                    probeEnabled = true,
                    nowMillis = at,
                    scheduleRetry = { retryAt -> MorningAuthRuntime.scheduleProbeRetry(appContext, retryAt) }
                )
            ) {
                ProbeRetryCoordinator.Action.WAIT, ProbeRetryCoordinator.Action.GIVE_UP -> {
                    val msg = "探测闸门（周期任务）：距上次探测不足 5 分钟或重试额度已用尽 → 本次不探测、不登录"
                    runCatching { AppLog.record(logStore, "调度：[periodic] $msg") }
                    val r = AuthRunResult(
                        outcome = RunOutcome.WAITING,
                        code = "E_PROBE_WAIT",
                        message = msg,
                        authOk = false,
                        trigger = trigger,
                        attempt = 0,
                        attemptsConsumed = false,
                        finishedAtMillis = at,
                        delaySeconds = 0L,
                        ranFlow = false,
                        statusLine = ""
                    )
                    return r
                }
                else -> Unit
            }
        } else {
            ProbeRetryCoordinator.reset(logStore, gateSsid)
        }

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
        // 【logfix1 任务 B 段】调度触发：把「谁唤起了这次认证、目标网络是哪个」写进应用内日志
        runCatching {
            AppLog.record(
                logStore,
                "调度：后台认证触发（trigger=${trigger.wireName}，periodic=$periodic，" +
                    "当前 SSID=${currentSsid ?: "未读到"}，目标 SSID=${target ?: "无"}）"
            )
        }
        val result = run.coordinator.run(target)
        // 【logfix1 任务 B 段】重试排期：把「第几次 + 延迟多少秒」记下来（与 AuthJobService 的
        // enqueueAuth 一一对应；在这里记是因为它同时覆盖 JobService 与「原地 run」两条调用路径）。
        if (result.outcome == RunOutcome.RETRY_SCHEDULED || result.outcome == RunOutcome.SKIPPED_ZERO_REQUEST) {
            runCatching {
                AppLog.record(
                    logStore,
                    "调度：安排重试（第 ${result.attempt}/${maxAttempts(appContext)} 次，延迟 ${result.delaySeconds}s，" +
                        "原因 ${result.code}）"
                )
            }
        }
        return result
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
