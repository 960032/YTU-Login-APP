package top.ytu.srunautologin.flow

import top.ytu.srunautologin.auth.AuthFailure
import top.ytu.srunautologin.auth.AuthRequest
import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.auth.AuthTransport
import top.ytu.srunautologin.net.WifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.storage.Credential
import top.ytu.srunautologin.storage.CredentialRepository
import top.ytu.srunautologin.storage.WifiAccountMap

/**
 * 认证编排（模块 flow）——纯逻辑，不引用任何 Android API，可离线测试。
 *
 * 流程：读当前 SSID → 查 WiFi↔账号绑定（label）→ 取凭据 → 调认证客户端 → 记录结果。
 *
 * 【B8 判据】只有当**当前 SSID 与已绑定的目标 SSID 匹配**时才发起认证；
 * 不匹配时**不发任何请求**（零次 transport 调用），返回 [AuthSkipReason] 描述的 Skipped 结果。
 *
 * 依赖全部通过接口注入（[CredentialLookup] / [WifiAccountLookup] / [WifiSnapshotPort] / [AuthTransport]），
 * 因此可在 JVM 上用手写假实现完成离线验证——不需要真机、不需要网络。
 */

/* ============================ 依赖端口 ============================ */

/** 凭据查询端口（真机实现：包裹 storage 包的 CredentialRepository）。 */
interface CredentialLookup {
    fun find(label: String): Credential?

    /** 当前选中项；无选中项返回 null。 */
    fun selected(): Credential?
}

/**
 * 「该 WiFi 是否有**已勾选**的账号」查询端口（accountsel1 任务新增，真机实现：storage.AccountStore）。
 *
 * 为什么需要它：只靠 [WifiAccountLookup] 拦不住「未勾选的账号仍被认证」——
 * AuthFlow 在拿不到绑定 label 时还会用 [CredentialLookup.selected] 兜底（selected_label_v1），
 * 于是「未勾选」会被兜底路径绕过。有了本端口，AuthFlow 在同一次判定里多做一步：
 * **未勾选 ⇒ 不发请求**（code = SSID_NOT_BOUND，与「该 WiFi 未绑定账号」同类跳过）。
 *
 * 默认实现是 null（构造参数默认值），因此既有调用点与既有离线核对的 class 快照**不受影响**；
 * 只有真机装配点（MainActivity / AuthWorkWiring）显式传入。
 */
interface EnabledAccountLookup {
    /** 该 SSID 是否存在已勾选的账号；SSID 为空/无绑定/未勾选一律 false。 */
    fun hasEnabledAccountFor(ssid: String?): Boolean
}

/** WiFi↔账号绑定查询端口（真机实现：包裹 storage 包的 WifiAccountMap）。 */
interface WifiAccountLookup {
    /** 该 SSID 绑定的账号 label；未绑定返回 null。 */
    fun labelFor(ssid: String?): String?
}

/** WiFi 快照端口（真机实现：包裹 net 包的 WifiSnapshotCore）。 */
interface WifiSnapshotPort {
    fun currentSsid(): String?
}

/**
 * Portal 地址提供者（可配置）。
 *
 * 注意：本应用**不硬编码本机 IP**——请求中的 ip 字段由认证客户端从
 * get_challenge 响应的 client_ip 取得，取不到时才用 Socket.localAddress 探测；
 * 这里的 portal 只是「门户主机地址」，由用户在配置界面填写并持久化
 * （实现见 [StoredPortalProvider]，默认值见 [AuthFlow.DEFAULT_PORTAL]）。
 */
interface PortalProvider {
    fun portal(): String
}

/* ============================ 结果类型 ============================ */

/** 跳过认证的原因（B8：不匹配则零请求）。 */
enum class AuthSkipReason(val code: String) {
    /** 当前没有连接 WiFi / 读不到 SSID。 */
    NO_CURRENT_SSID("E_SKIP_NO_SSID"),

    /** 当前 SSID 没有绑定任何账号。 */
    SSID_NOT_BOUND("E_SKIP_UNBOUND"),

    /** 当前 SSID 已绑定，但**与本次认证的目标 SSID 不一致**。 */
    SSID_MISMATCH("E_SKIP_SSID_MISMATCH")
}

/** AuthFlow 的最终结果：Skipped（零请求）或 Done（真的调用过认证客户端）。 */
sealed interface AuthFlowOutcome {
    /** 已按 [AuthSkipReason] 跳过，未发出任何认证请求。 */
    data class Skipped(
        val reason: AuthSkipReason,
        val currentSsid: String?,
        val targetSsid: String?
    ) : AuthFlowOutcome

    /** 认证客户端返回的结构化结果（成功或失败）。 */
    data class Done(
        val result: AuthResult,
        val currentSsid: String?,
        val targetSsid: String,
        val label: String
    ) : AuthFlowOutcome
}

/** 跳过原因 → 结构化 AuthResult（供 UI 状态区统一展示）。 */
object AuthSkip {
    fun toResult(outcome: AuthFlowOutcome.Skipped, elapsedMs: Long = 0L): AuthResult {
        val msg = when (outcome.reason) {
            AuthSkipReason.NO_CURRENT_SSID ->
                "未连接 WiFi，未发起认证（当前无可用 SSID）"
            AuthSkipReason.SSID_NOT_BOUND ->
                "当前 WiFi「${outcome.currentSsid}」未绑定账号，未发起认证"
            AuthSkipReason.SSID_MISMATCH ->
                "当前 WiFi「${outcome.currentSsid}」与目标 WiFi「${outcome.targetSsid}」不一致，未发起认证"
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

/* ============================ 编排实现 ============================ */

/**
 * @param credentials  凭据查询
 * @param wifiMap      WiFi↔账号绑定查询
 * @param wifiSnapshot 当前 SSID 读取（降级时可能返回 null）
 * @param transport    认证客户端（网络层注入点）
 * @param portalProvider Portal 主机地址提供者
 * @param clock        取当前时间（毫秒），便于离线测试注入固定时钟
 */
class AuthFlow(
    private val credentials: CredentialLookup,
    private val wifiMap: WifiAccountLookup,
    /**
     * 【accountsel1 任务 C 段】已勾选账号端口（真机传 storage.AccountStore；默认 null = 不做该判定）。
     * 见 [EnabledAccountLookup] 的 KDoc：它拦住「未勾选却被 selected 兜底认证」这条路径。
     */
    private val enabledAccounts: EnabledAccountLookup? = null,
    private val wifiSnapshot: WifiSnapshotPort,
    private val transport: AuthTransport,
    private val portalProvider: PortalProvider = defaultPortalProvider,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {

    /** 记录最近一次结果（供状态显示区读取；失败不静默）。 */
    var lastResult: AuthResult? = null
        private set

    var lastAttemptAtMillis: Long = 0L
        private set

    var lastOutcome: AuthFlowOutcome? = null
        private set

    /**
     * 执行一次自动认证。
     *
     * @param targetSsid 目标 SSID（通常是用户在配置界面选定的 WiFi）。
     *                   为 null/空时退化为「以当前 SSID 为准」（用户手动点「立即登录」的场景）。
     */
    fun run(targetSsid: String?): AuthFlowOutcome {
        val started = clock()
        val current = wifiSnapshot.currentSsid()
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
        // 步骤 1：当前 SSID 必须可读（读不到 → 不发请求）
        if (current.isNullOrBlank()) {
            return AuthFlowOutcome.Skipped(AuthSkipReason.NO_CURRENT_SSID, null, targetSsid)
        }

        // 步骤 2a（accountsel1 任务 C 段）：**未勾选的账号不参与认证**。
        // 必须在「查绑定关系」之前判：若放到步骤 4 之后，`credentials.selected()` 的兜底会把
        // 「本 WiFi 绑定的账号被用户取消勾选」这种情况重新认证出去。
        // enabledAccounts == null 表示调用方未启用该判定（既有离线核对的老调用点），行为与改动前一致。
        if (enabledAccounts != null && !enabledAccounts.hasEnabledAccountFor(current)) {
            return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_NOT_BOUND, current, targetSsid)
        }

        // 步骤 2：查绑定关系
        val boundLabel = wifiMap.labelFor(current)
            ?: return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_NOT_BOUND, current, targetSsid)

        // 步骤 3（B8 核心）：目标 SSID 与当前 SSID 必须一致，否则零请求返回
        val effectiveTarget = if (targetSsid.isNullOrBlank()) current else targetSsid.trim()
        if (current.trim() != effectiveTarget) {
            return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_MISMATCH, current, effectiveTarget)
        }

        // 步骤 4：取凭据（缺失 → 结构化失败，仍然不发请求）
        val credential = credentials.find(boundLabel) ?: credentials.selected()
        if (credential == null) {
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

        // 步骤 5：调认证客户端（唯一发请求的地方）
        val request = AuthRequest(
            username = credential.username,
            password = credential.password,
            acId = credential.acId,   // 已冻结：字符串 "5"
            portal = portalProvider.portal(),
            ipOverride = ""           // 空 = 由认证客户端按 client_ip → 本机探测 的顺序决定（绝不硬编码）
        )
        return AuthFlowOutcome.Done(transport.execute(request), current, effectiveTarget, boundLabel)
    }

    companion object {
        /**
         * 默认 Portal 主机（烟台大学 SRun 门户，已用参考脚本实测可用）。
         *
         * 用户可在配置界面的 Portal 地址输入框中覆盖；覆盖值存于键值存储，
         * 生效优先序：**用户保存的值 > 本默认值**（见 `storage/PortalConfig.kt`）。
         * 本常量保持唯一字面量来源，其它地方不得再写字面量地址。
         */
        const val DEFAULT_PORTAL: String = "202.194.116.116"

        /** 使用默认 Portal 的 [PortalProvider]（无配置存储时的兜底；真机用 [StoredPortalProvider]）。 */
        val defaultPortalProvider: PortalProvider = object : PortalProvider {
            override fun portal(): String = DEFAULT_PORTAL
        }
    }
}

/* ============================ 真机装配适配器 ============================ */

/** 用 storage 包的 [CredentialRepository] 实现 [CredentialLookup]。 */
class RepositoryCredentialLookup(private val repo: CredentialRepository) : CredentialLookup {
    override fun find(label: String): Credential? = repo.find(label)
    override fun selected(): Credential? = repo.selected()
}

/** 用 storage 包的 [WifiAccountMap] 实现 [WifiAccountLookup]。 */
class MapWifiAccountLookup(private val map: WifiAccountMap) : WifiAccountLookup {
    override fun labelFor(ssid: String?): String? = map.labelFor(ssid)
}

/** 用 net 包的 [WifiSnapshotCore] 实现 [WifiSnapshotPort]。 */
class CoreWifiSnapshotPort(private val core: WifiSnapshotCore) : WifiSnapshotPort {
    override fun currentSsid(): String? = core.currentSsid()
}

/**
 * 认证客户端工厂接口：让「立即登录」与后台调度复用同一套装配，
 * 同时保持 flow 模块对 auth 模块实现的弱耦合（测试可注入假 transport）。
 */
interface AuthTransportFactory {
    fun create(): AuthTransport
}

/** 权限状态到「当前 SSID 是否可读」的说明（UI 展示用，纯逻辑）。 */
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

    /** 权限流程接口 [WifiPermissionFlow] 的说明文案转发（保证 UI 与冻结契约同源）。 */
    fun explain(flow: WifiPermissionFlow): String = flow.explainText

    /** 顺序说明（供报告与 UI 文案引用，逐字对应需求原文）。 */
    const val ORDER: String = "explainText 展示说明 → markRationaleShown() → 系统弹窗 → onRequestResult(...)"
}
