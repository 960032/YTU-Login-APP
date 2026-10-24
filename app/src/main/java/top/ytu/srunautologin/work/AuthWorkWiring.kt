package top.ytu.srunautologin.work

import android.content.Context
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.CoreWifiSnapshotPort
import top.ytu.srunautologin.flow.CredentialLookup
import top.ytu.srunautologin.flow.MapWifiAccountLookup
import top.ytu.srunautologin.flow.PortalProvider
import top.ytu.srunautologin.flow.ProbePort
import top.ytu.srunautologin.flow.StoredPortalProvider
import top.ytu.srunautologin.log.AppLog
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.platform.AndroidAuthSessionFactory
import top.ytu.srunautologin.platform.AndroidWifiPermissionFlow
import top.ytu.srunautologin.platform.AndroidWifiSource
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.platform.WifiSnapshot
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.storage.CredentialRepository

class StorageCredentialLookup(private val repo: CredentialRepository) : CredentialLookup {
    override fun find(label: String): Credential? = repo.find(label)
    override fun selected(): Credential? = repo.selected()
    fun list(): List<Credential> = repo.list()
}

object DefaultPortalProvider : PortalProvider {
    override fun portal(): String = AuthFlow.DEFAULT_PORTAL
}

fun portalProviderFrom(context: Context): PortalProvider =
    StoredPortalProvider(SrunStorage.keyValueStore(context.applicationContext))

class AndroidAuthRunEnv(context: Context, private val minRetryIntervalSeconds: Long) : AuthRunEnv {
    private val app = context.applicationContext
    private val credentials = StorageCredentialLookup(SrunStorage.credentialRepository(app))
    private val wifiMap = SrunStorage.wifiAccountMap(app)
    private val accounts = SrunStorage.accountStore(app)
    private val wifiSnapshot = WifiSnapshotCore(AndroidWifiSource(app), AndroidWifiPermissionFlow(app))
    override fun currentSsid(): String? = wifiSnapshot.currentSsid()

    override fun buildRun(trigger: TriggerKind, minRetryIntervalSeconds: Long): AuthRun {
        val flow = AuthFlow(
            credentials = credentials,
            wifiMap = accounts,
            enabledAccounts = accounts,
            wifiSnapshot = CoreWifiSnapshotPort(wifiSnapshot),
            portalProvider = portalProviderFrom(app),
            sessionFactory = AndroidAuthSessionFactory(app, automatic = true)
        ).withProbeAndLog(ProbePort.inactive, null) { AppLog.record(SrunStorage.keyValueStore(app), it) }
        val coordinator = AuthWorkCoordinator(flow, AuthStatusStore(SrunStorage.keyValueStore(app)),
            BackoffScheduler(), trigger, minRetryIntervalSeconds = minRetryIntervalSeconds)
        coordinator.log = { AppLog.record(SrunStorage.keyValueStore(app), it) }
        return AuthRun(coordinator, currentSsid())
    }

    fun boundSsids(): List<String> = accounts.enabled().map { it.ssid }.filter(String::isNotBlank)
    fun hasCredential(): Boolean = accounts.list().isNotEmpty()
}

object AuthWorkWiring {
    private const val PROGRESS_KEY = "srun_auth_progress_v1"
    private const val MAX_PROGRESS_CHARS = 4000
    private fun kv(context: Context) = SrunStorage.keyValueStore(context.applicationContext)
    fun keyValueStore(context: Context) = kv(context)
    fun progressRecorder(context: Context) = AuthStatusStore(kv(context))
    fun scheduler(context: Context) = AndroidAuthScheduler(context.applicationContext)
    fun retryPolicy(context: Context): RetryPolicy = BackoffScheduler().policy
    fun maxAttempts(context: Context): Int = retryPolicy(context).maxAttempts
    fun periodicDebounceSeconds(): Long = 30L

    fun resetBackoff(context: Context, clearUserAction: Boolean = false) {
        val store = AuthStatusStore(kv(context))
        store.clearAttempts(seq = store.loadAttemptState().seq)
        if (clearUserAction) store.setUserActionRequired(false)
    }

    @Synchronized
    fun progress(context: Context, line: String) {
        try {
            val store = kv(context)
            val safeLine = AppLog.sanitize(line)
            val previous = store.getString(PROGRESS_KEY).orEmpty()
            val entry = "[${AuthStatusStore.formatTime(System.currentTimeMillis())}] $safeLine\n"
            store.putString(PROGRESS_KEY, (previous + entry).takeLast(MAX_PROGRESS_CHARS))
            AppLog.record(store, safeLine)
        } catch (_: RuntimeException) { }
    }

    fun progressLog(context: Context): String = kv(context).getString(PROGRESS_KEY).orEmpty()

    fun run(context: Context, trigger: TriggerKind, periodic: Boolean = false, targetOverride: String? = null): AuthRunResult {
        val app = context.applicationContext
        val now = System.currentTimeMillis()
        val store = AuthStatusStore(kv(app))
        fun blocked(outcome: RunOutcome, code: String, message: String): AuthRunResult {
            val status = AuthStatusStore.formatLine(trigger, now, false, code, message,
                "配置或权限", 0, maxAttempts(app))
            store.saveResult(status, code, false, now)
            progress(app, "调度：$message（code=$code）")
            return AuthRunResult(outcome, code, message, false, trigger, 0, false, now, 0, false, status)
        }
        if (!AutoLoginSwitch.isEnabled(kv(app))) {
            return blocked(RunOutcome.WAITING, "E_DISABLED", "自动登录已停用，本次未发起请求")
        }
        val capability = WifiSnapshot.capability(app)
        if (capability.degraded) {
            return blocked(RunOutcome.NO_PERMISSION, "E_NO_WIFI_PERMISSION",
                "无法读取目标 WiFi，请打开应用检查精确位置权限和系统位置信息开关")
        }
        val env = AndroidAuthRunEnv(app, periodicDebounceSeconds())
        val hasCredential = try { env.hasCredential() } catch (_: Exception) {
            return blocked(RunOutcome.NO_CREDENTIAL, "E_CONFIG", "保存的账号无法读取，已保留原有数据，请打开应用检查")
        }
        if (!hasCredential && targetOverride == null) {
            val result = AuthFlowRunner.noCredentialResult(trigger, now, maxAttempts(app))
            store.saveResult(result.statusLine, result.code, false, now)
            progress(app, "调度：尚未保存账号，本次未发起请求")
            return result
        }
        // A later periodic wake starts a fresh transient-failure campaign. Permanent
        // credential/configuration failures remain blocked until the user changes them.
        val previous = store.loadAttemptState()
        if (periodic && previous.attempts >= maxAttempts(app) &&
            now - previous.lastRequestAtMillis >= 15 * 60_000L &&
            !store.userActionRequired(env.currentSsid())) {
            resetBackoff(app)
        }
        val current = env.currentSsid()
        val target = targetOverride?.takeIf(String::isNotEmpty)
            ?: AuthFlowRunner.targetOf(current, null, env.boundSsids())
        progress(app, "调度：后台认证触发（trigger=${trigger.wireName}，periodic=$periodic，WiFi=${current ?: "不可读取"}）")
        val result = env.buildRun(trigger, if (periodic) periodicDebounceSeconds() else 0L).coordinator.run(target)
        progress(app, "调度：后台任务完成 outcome=${result.outcome.wireName} code=${result.code} delay=${result.delaySeconds}s")
        return result
    }

    fun onTrigger(context: Context, reason: String, initialDelayMillis: Long) {
        AutoLoginController.restore(context, reason)
        AutoLoginController.requestCheck(context, reason, delayMillis = initialDelayMillis)
    }
}
