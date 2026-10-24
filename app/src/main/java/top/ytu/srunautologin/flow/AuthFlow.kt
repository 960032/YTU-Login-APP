package top.ytu.srunautologin.flow

import top.ytu.srunautologin.auth.AuthFailure
import top.ytu.srunautologin.auth.AuthRequest
import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.auth.AuthTransport
import top.ytu.srunautologin.auth.SrunProtocol
import top.ytu.srunautologin.log.AppLog
import top.ytu.srunautologin.net.WifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.storage.CredentialRepository
import top.ytu.srunautologin.storage.WifiAccountMap
import top.ytu.srunautologin.auth.AuthCodes
import top.ytu.srunautologin.auth.PortalEndpoint
import java.io.IOException

interface CredentialLookup {
    fun find(label: String): Credential?

    fun selected(): Credential?
}

interface EnabledAccountLookup {
    val providesCredentials: Boolean get() = false
    fun credentialForSsid(ssid: String): Credential? = null
    fun hasEnabledAccountFor(ssid: String?): Boolean
}

interface WifiAccountLookup {
    fun labelFor(ssid: String?): String?
}

interface WifiSnapshotPort {
    fun currentSsid(): String?
}

interface PortalProvider {
    fun portal(): String
    fun allowInsecureHttp(): Boolean = false
    fun settings(): top.ytu.srunautologin.auth.PortalConnectionSettings =
        top.ytu.srunautologin.auth.PortalConnectionSettings(portal(), allowInsecureHttp())
}

enum class AuthSkipReason(val code: String) {
    IN_PROGRESS("E_SKIP_IN_PROGRESS"),
    NO_CURRENT_SSID("E_SKIP_NO_SSID"),

    SSID_NOT_BOUND("E_SKIP_UNBOUND"),

    SSID_MISMATCH("E_SKIP_SSID_MISMATCH"),

    NOT_SRUN("E_SKIP_NOT_SRUN"),

    ALREADY_ONLINE("E_SKIP_ALREADY_ONLINE"),

    PROBE_UNCERTAIN("E_SKIP_PROBE_UNCERTAIN")
}

sealed interface AuthFlowOutcome {
    data class Skipped(
        val reason: AuthSkipReason,
        val currentSsid: String?,
        val targetSsid: String?
    ) : AuthFlowOutcome

    data class Done(
        val result: AuthResult,
        val currentSsid: String?,
        val targetSsid: String,
        val label: String
    ) : AuthFlowOutcome
}

object AuthSkip {
    fun toResult(outcome: AuthFlowOutcome.Skipped, elapsedMs: Long = 0L): AuthResult {
        val msg = when (outcome.reason) {
            AuthSkipReason.IN_PROGRESS -> "已有一轮认证正在执行，已合并本次触发"
            AuthSkipReason.NO_CURRENT_SSID ->
                "未连接 WiFi，未发起认证（当前无可用 SSID）"
            AuthSkipReason.SSID_NOT_BOUND ->
                "当前 WiFi「${outcome.currentSsid}」未绑定账号，未发起认证"
            AuthSkipReason.SSID_MISMATCH ->
                "当前 WiFi「${outcome.currentSsid}」与目标 WiFi「${outcome.targetSsid}」不一致，未发起认证"
            AuthSkipReason.NOT_SRUN ->
                "当前 WiFi「${outcome.currentSsid}」不是 SRun 认证系统，未发起认证（判定依据见日志）"
            AuthSkipReason.ALREADY_ONLINE ->
                "当前 WiFi「${outcome.currentSsid}」已处于登录状态，无需重复登录"
            AuthSkipReason.PROBE_UNCERTAIN ->
                "无法确认当前 WiFi「${outcome.currentSsid}」是否为 SRun 系统及其登录状态" +
                    "（探测不确定，将按 5 分钟间隔最多重试 2 次），本次未发起认证"
        }
        return AuthResult(
            ok = false,
            code = outcome.reason.code,
            msg = msg,
            stage = "skip",
            elapsedMs = elapsedMs,
            failure = AuthFailure.CONFIG_MISSING,
            ipSource = ""
        )
    }
}

class AuthFlow(
    private val credentials: CredentialLookup,
    private val wifiMap: WifiAccountLookup,
    private val enabledAccounts: EnabledAccountLookup? = null,
    private val wifiSnapshot: WifiSnapshotPort,
    private val transport: AuthTransport = AuthTransport {
        AuthResult.failure(AuthFailure.CONFIG_MISSING, AuthCodes.E_CONFIG,
            "未配置认证网络会话", "network", 0L)
    },
    private val portalProvider: PortalProvider = defaultPortalProvider,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val sessionFactory: AuthSessionFactory? = null
) {

    var probeGate: ProbePort = ProbePort.inactive

    var probeAttempts: ProbeAttemptStore? = null

    var logWriter: ((String) -> Unit)? = null

    fun withProbeAndLog(
        probeGate: ProbePort,
        probeAttempts: ProbeAttemptStore?,
        logWriter: ((String) -> Unit)?
    ): AuthFlow {
        this.probeGate = probeGate
        this.probeAttempts = probeAttempts
        this.logWriter = logWriter
        return this
    }

    var lastResult: AuthResult? = null
        private set

    var lastAttemptAtMillis: Long = 0L
        private set

    var lastOutcome: AuthFlowOutcome? = null
        private set

    private var lastLoggedSsid: String? = "<首次运行>"

    val lastProbeState: ProbeAttemptState? get() = lastProbe

    private var lastProbe: ProbeAttemptState? = null

    fun run(targetSsid: String?): AuthFlowOutcome {
        if (!AuthenticationGate.tryEnter()) {
            return AuthFlowOutcome.Skipped(AuthSkipReason.IN_PROGRESS, null, targetSsid)
        }
        return try { runExclusive(targetSsid) }
        catch (_: top.ytu.srunautologin.storage.SecureStoreException) {
            val result = AuthResult.failure(AuthFailure.CONFIG_MISSING, AuthCodes.E_CONFIG,
                "保存的凭据无法解密，已保留原有数据，请检查账号设置", "config", 0)
            lastResult = result
            AuthFlowOutcome.Done(result, null, targetSsid.orEmpty(), "")
        } finally { AuthenticationGate.leave() }
    }

    private fun runExclusive(targetSsid: String?): AuthFlowOutcome {
        val started = clock()
        val current = wifiSnapshot.currentSsid()
        if (current != null && current != lastLoggedSsid) {
            log("网络检测：检测到网络变化（上次「$lastLoggedSsid」，当前「$current」）")
        }
        lastLoggedSsid = current
        if (current == null) {
            log("网络检测：未能读到当前 SSID（可能是未连接 WiFi / 未授予位置信息权限 / 系统未返回）→ 跳过登录")
        } else {
            log("网络检测：当前 SSID=「$current」")
        }
        val outcome = runInternal(targetSsid, current, started)
        lastOutcome = outcome
        lastAttemptAtMillis = clock()
        lastResult = when (outcome) {
            is AuthFlowOutcome.Skipped -> AuthSkip.toResult(outcome, lastAttemptAtMillis - started)
            is AuthFlowOutcome.Done -> outcome.result
        }
        return outcome
    }

    private fun runInternal(targetSsid: String?, current: String?, started: Long): AuthFlowOutcome {
        if (current.isNullOrBlank()) {
            return AuthFlowOutcome.Skipped(AuthSkipReason.NO_CURRENT_SSID, null, targetSsid)
        }

        if (enabledAccounts != null && !enabledAccounts.hasEnabledAccountFor(current)) {
            return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_NOT_BOUND, current, targetSsid)
        }

        val boundLabel = wifiMap.labelFor(current)
            ?: run {
                log("网络检测：当前 WiFi「$current」没有匹配到任何已存储的网络（未绑定账号）→ 跳过登录")
                return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_NOT_BOUND, current, targetSsid)
            }
        log("网络检测：当前 WiFi「$current」与已存储网络**匹配**（账号 label=「$boundLabel」）")

        val effectiveTarget = if (targetSsid.isNullOrBlank()) current else targetSsid
        if (current != effectiveTarget) {
            log("网络检测：当前 WiFi「$current」与目标 WiFi「$effectiveTarget」**不匹配** → 跳过登录")
            return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_MISMATCH, current, effectiveTarget)
        }

        val credential = if (enabledAccounts?.providesCredentials == true)
            enabledAccounts.credentialForSsid(current) else credentials.find(boundLabel)
        if (credential == null) {
            log("配置检查：WiFi「$current」绑定到账号「$boundLabel」，但未找到该账号凭据 → 未发起认证")
            return AuthFlowOutcome.Done(
                AuthResult(
                    ok = false,
                    code = "E_CONFIG",
                    msg = "WiFi「$current」绑定到账号「$boundLabel」，但未找到该账号凭据",
                    stage = "config",
                    elapsedMs = clock() - started,
                    failure = AuthFailure.CONFIG_MISSING
                ),
                current, effectiveTarget, boundLabel
            )
        }

        val settings = portalProvider.settings()
        val portal = PortalEndpoint.normalize(settings.origin)
        val cleartextAllowed = settings.allowInsecureHttp
        if (portal == null || (PortalEndpoint.isCleartext(portal) && !cleartextAllowed)) {
            val result = AuthResult.failure(
                AuthFailure.CONFIG_MISSING,
                if (portal == null) AuthCodes.E_CONFIG else AuthCodes.E_INSECURE_PORTAL,
                if (portal == null) "门户地址无效，请检查配置"
                else "此门户使用 HTTP，请先在门户设置中确认允许不加密的登录连接",
                "config", clock() - started
            )
            log("配置检查：${result.msg}")
            return AuthFlowOutcome.Done(result, current, effectiveTarget, boundLabel)
        }
        val session = try { sessionFactory?.open(current) }
        catch (_: IOException) {
            return AuthFlowOutcome.Done(
                AuthResult.failure(AuthFailure.NETWORK_UNREACHABLE, AuthCodes.E_WIFI_CHANGED,
                    "无法锁定目标 WiFi，本轮未发起认证", "network", clock() - started),
                current, effectiveTarget, boundLabel
            )
        }
        return try {
            authenticate(credential, current, effectiveTarget, boundLabel, started, portal,
                cleartextAllowed, session?.transport ?: transport, session?.probe ?: probeGate)
        } finally { session?.close() }
    }

    private fun authenticate(
        credential: Credential, current: String, effectiveTarget: String, boundLabel: String,
        started: Long, portal: String, cleartextAllowed: Boolean,
        runTransport: AuthTransport, runProbe: ProbePort
    ): AuthFlowOutcome {
        if (runProbe !== ProbePort.inactive) {
            val probe = runProbe.probe(portal, credential.username, "")
            val safeUser = AppLog.maskAccount(credential.username)
            when (probe.outcome) {
                ProbeOutcome.NOT_SRUN -> {
                    probeAttempts?.reset(current)
                    log("网络检测：WiFi「$current」判定为**非 SRun 系统**（依据：${probe.evidence}）→ 跳过登录")
                    return AuthFlowOutcome.Skipped(AuthSkipReason.NOT_SRUN, current, effectiveTarget)
                }
                ProbeOutcome.ALREADY_ONLINE -> {
                    probeAttempts?.reset(current)
                    log("网络检测：WiFi「$current」是 SRun 系统且**已登录**（依据：${probe.evidence}）→ 跳过登录")
                    return AuthFlowOutcome.Skipped(AuthSkipReason.ALREADY_ONLINE, current, effectiveTarget)
                }
                ProbeOutcome.INDETERMINATE -> {
                    probeAttempts?.reset(current)
                    lastProbe = null
                    log(
                        "网络检测：WiFi「$current」探测**不确定**（依据：${probe.evidence}）" +
                            "→ **降级为继续执行认证**（探测只是优化，不应阻止登录；5 分钟重试通道不再使用）"
                    )
                }
                ProbeOutcome.NOT_LOGGED_IN -> {
                    probeAttempts?.reset(current)
                    log("网络检测：WiFi「$current」未检测到已登录状态，将尝试认证（依据：${probe.evidence}，账号 $safeUser）")
                }
            }
        }

        val request = AuthRequest(
            username = credential.username,
            password = credential.password,
            acId = credential.acId,   // 已冻结：字符串 "5"
            portal = portal,
            ipOverride = "",
            allowInsecureHttp = cleartextAllowed
        )
        log("登录执行：开始认证（目标 WiFi「$current」，账号 ${AppLog.maskAccount(credential.username)}，门户 $portal）")
        val result = runTransport.execute(request)
        if (result.ok) {
            log("登录执行：成功（服务端 error=${SrunProtocol.OK}，阶段 ${result.stage}，耗时 ${result.elapsedMs}ms，ip 来源 ${result.ipSource}）")
        } else {
            if (SrunProbeClassifier.isAlreadyOnline(result.code, result.msg)) {
                log(
                    "登录执行：服务端返回**已在线**（code=${result.code}）：${result.msg}" +
                        " → 视同成功/跳过（不重试、不消耗退避预算）"
                )
                return AuthFlowOutcome.Skipped(AuthSkipReason.ALREADY_ONLINE, current, effectiveTarget)
            }
            log(
                "登录执行：失败（${result.failure?.displayName ?: "未分类"}，code=${result.code}，" +
                    "阶段 ${result.stage}，耗时 ${result.elapsedMs}ms）：${result.msg}"
            )
        }
        return AuthFlowOutcome.Done(result, current, effectiveTarget, boundLabel)
    }

    private fun log(line: String) {
        runCatching { logWriter?.invoke(line) }
    }

    companion object {
        const val DEFAULT_PORTAL: String = "https://202.194.116.116"

        val defaultPortalProvider: PortalProvider = object : PortalProvider {
            override fun portal(): String = DEFAULT_PORTAL
        }
    }
}

class RepositoryCredentialLookup(private val repo: CredentialRepository) : CredentialLookup {
    override fun find(label: String): Credential? = repo.find(label)
    override fun selected(): Credential? = repo.selected()
}

class MapWifiAccountLookup(private val map: WifiAccountMap) : WifiAccountLookup {
    override fun labelFor(ssid: String?): String? = map.labelFor(ssid)
}

class CoreWifiSnapshotPort(private val core: WifiSnapshotCore) : WifiSnapshotPort {
    override fun currentSsid(): String? = core.currentSsid()
}

interface AuthTransportFactory {
    fun create(): AuthTransport
}

object PermissionText {
    fun describe(state: WifiPermissionState): String = when (state) {
        WifiPermissionState.GRANTED -> "已授予 WiFi 权限：可读取当前 WiFi 并扫描列表"
        WifiPermissionState.NOT_REQUIRED -> "当前系统版本无需该权限：可读取当前 WiFi 并扫描列表"
        WifiPermissionState.DENIED -> "已拒绝 WiFi 权限：降级为**只检测当前连接的 WiFi**，不显示周边列表"
    }

    fun outcomeText(outcome: WifiPermissionRequestOutcome): String = when (outcome) {
        WifiPermissionRequestOutcome.GRANTED -> "已授权：WiFi 列表与当前连接均可用"
        WifiPermissionRequestOutcome.DENIED -> "已拒绝：降级为只检测当前 WiFi（可在系统设置中恢复）"
    }

    fun explain(flow: WifiPermissionFlow): String = flow.explainText

    const val ORDER: String = "explainText 展示说明 → markRationaleShown() → 系统弹窗 → onRequestResult(...)"
}
