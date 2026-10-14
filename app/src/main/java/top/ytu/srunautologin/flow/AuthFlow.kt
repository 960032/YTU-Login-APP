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

/**
 * 认证编排（模块 flow）——纯逻辑，不引用任何 Android API，可离线测试。
 *
 * 流程（logfix1 任务 C 段改造后的**四段判断链**，用户原话逐段对应）：
 *   ① 读当前 SSID → 与已存储的网络比对（WiFi↔账号绑定 + 已勾选判定）→ 不匹配：跳过（记日志）；
 *   ② 验证该网络是否为 SRun 认证系统（探测 [ProbePort]）→ 不是：跳过（记日志「非 SRun 系统」）；
 *   ③ 检查网络是否已登录（**与 ② 同一次探测**，不多打 Portal）→ 已登录：跳过（记日志「已在线」）；
 *   ④ 未登录 → 取凭据 → 调认证客户端执行登录。
 *
 * 【probefix1 任务 B 段·口径变更】②③ **不确定**（超时/无响应/无 error 字段）时 **不再跳过**，
 * 而是**降级为继续第 ④ 段认证**：探测只是优化（避免不必要的认证请求），探测本身不可靠时
 * 不应该阻止真正的登录。若网络其实已在线，服务端回的「已在线」文案会被第 ④ 段的
 * [AuthSkipReason.ALREADY_ONLINE] 兜住（判定见 [SrunProbeClassifier.isAlreadyOnline]）。
 * [AuthSkipReason.PROBE_UNCERTAIN] 与 [ProbeRetryPolicy] 的「5 分钟、最多 2 次」通道因此
 * **不再被本类触发**（保留枚举/策略常量是为了不改动 flow 之外的文件）。
 *
 * 【B8 判据（未改）】只有当**当前 SSID 与已绑定的目标 SSID 匹配**时才发起认证；
 * 不匹配时**不发任何请求**（零次 transport 调用），返回 [AuthSkipReason] 描述的 Skipped 结果。
 *
 * 依赖全部通过接口注入（[CredentialLookup] / [WifiAccountLookup] / [WifiSnapshotPort] / [AuthTransport] /
 * [ProbePort]），因此可在 JVM 上用手写假实现完成离线验证——不需要真机、不需要网络。
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
    SSID_MISMATCH("E_SKIP_SSID_MISMATCH"),

    /* ---- logfix1 任务 C 段（用户要求新增的第 ②③ 段判断）：探测不通过时跳过 ---- */

    /**
     * 【第 ② 段】探测结论：该网络**不是 SRun 认证系统** → 跳过登录（零认证请求）。
     * 用户原话：「验证该网络是否为SRun认证系统，若为该系统则检查网络是否已登录」。
     */
    NOT_SRUN("E_SKIP_NOT_SRUN"),

    /**
     * 【第 ③ 段】探测结论：**已登录**（服务端返回「已在线」类业务码）→ 跳过登录。
     * 用户原话：「检查网络是否已登录，若未登录则执行自动登录」。
     *
     * 【probefix1 任务 A 段·第二来源】认证请求发出后，若 `srun_portal` 的失败响应本身就是
     * 「已在线」（用户逐字指示：「"You are already online"即代表当前网络已经在线,无需登录」；
     * 真机实测 `code=E2620`、`msg=E2620: You are already online.`），也归到本枚举 →
     * **视同成功/跳过**：不重试、不消耗退避预算（`E_SKIP_` 前缀 = 零请求跳过口径，
     * 见 `work.RetryPolicy.SKIP_CODE_PREFIX`）。
     */
    ALREADY_ONLINE("E_SKIP_ALREADY_ONLINE"),

    /**
     * 【第 ②③ 段】探测**不确定**（超时 / 无响应 / 无 error 字段）→ 本次不登录，
     * 交给 [ProbeRetryPolicy] 的「5 分钟、最多 2 次重试」通道。
     * 注意：本值是**零请求跳过**（`E_SKIP_` 前缀），因此**不消耗** [AuthWorkCoordinator] 的退避预算，
     * 也不会与早上 6:00 的 7 次重试叠加（完整状态机见 artifacts/logfix1/fix-report.md）。
     */
    PROBE_UNCERTAIN("E_SKIP_PROBE_UNCERTAIN")
}

/** AuthFlow 的最终结果：Skipped 或 Done（真的调用过认证客户端）。 */
sealed interface AuthFlowOutcome {
    /**
     * 已按 [AuthSkipReason] 跳过。
     *
     * 【probefix1 任务 A 段】绝大多数情况是**零请求**跳过（第 ①②③ 段判定不出认证请求）；
     * **唯一例外**：认证请求已经发出、而服务端回的失败响应其实是「已在线」
     * （[AuthSkipReason.ALREADY_ONLINE] 的第二来源）时也返回本类型 —— 语义仍是
     * 「无需登录、不再重试」，且 code 带 `E_SKIP_` 前缀，因此不消耗退避预算。
     */
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

/* ============================ 编排实现 ============================ */

/**
 * @param credentials  凭据查询
 * @param wifiMap      WiFi↔账号绑定查询
 * @param wifiSnapshot 当前 SSID 读取（降级时可能返回 null）
 * @param transport    认证客户端（网络层注入点）
 * @param portalProvider Portal 主机地址提供者
 * @param clock        取当前时间（毫秒），便于离线测试注入固定时钟
 * @param probeGate    【logfix1 任务 C 段】**SRun 探测端口**（真机 `SrunPortalProbe`）。
 *                     默认 [ProbePort.inactive] = 不启用探测 → 行为与改造前完全一致（老调用点/离线核对不受影响）。
 *                     即 `probeGate` 只负责「发一次 get_challenge 并给结论」，判断链的走向仍由本类唯一决定。
 * @param probeAttempts 【logfix1 任务 C 段】探测重试计数（键 `srun_probe_attempt_v1`）。
 *                     非 null 时：探测出确定结论会复位计数；不确定时会记一次并写日志。
 *                     为 null（默认）= 纯内存流程（离线核对的老调用点），不做任何持久化。
 *                     注意：**不确定时的 5 分钟重试排期不在这里**，由 [top.ytu.srunautologin.work.ProbeRetryCoordinator]
 *                     统一负责（保证与既有 RetryPolicy / 早上 7 次重试不叠加）。
 * @param logContext   【logfix1 任务 B 段】日志写入用的 Android Context（真机传 applicationContext）。
 *                     为 null 时本类不写应用内日志（离线核对的纯 JVM 场景）。
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

    /**
     * 【logfix1 任务 C 段】SRun 探测端口（第 ②③ 段判断的注入点）。
     *
     * **为什么是可变属性 + 构造后 setter，而不是新增构造参数**（这是本次踩过的真坑）：
     * 既有离线核对程序（`verify-common-client` / `android-ci` 的**既有 class 快照**）是按
     * 「7 个参数 + 1 个默认掩码」的**合成默认构造**直接调用的：
     * `(CredentialLookup, WifiAccountLookup, EnabledAccountLookup, WifiSnapshotPort, AuthTransport,
     * PortalProvider, Function0<Long>, int, DefaultConstructorMarker)`。
     * 只要在构造参数列表里新增/移动任何一项，Kotlin 生成的合成默认构造的 JVM 描述符就会变
     * （实测：新增 3 个参数后变成 12 个参数），快照侧立刻抛
     * `java.lang.NoSuchMethodError: 'void ...AuthFlow.<init>(...Function0, int, DefaultConstructorMarker)'`
     * ——run-verification 两次实测都抓到（见 artifacts/logfix1/verify-proof.txt）。
     *
     * 因此**构造签名保持逐字冻结**，探测相关的三个依赖改为构造后注入：
     *  - 不设置 → 行为与改造前完全一致（`ProbePort.inactive`、不记账、不写日志）；
     *  - 真机装配点（`AndroidAuthRunEnv.buildRun` / `MainActivity.buildAuthFlow`）在创建后立即设置。
     * 这三个属性只在**装配期**（构造完成后立刻）写入，运行期只读，因此不引入并发风险。
     */
    var probeGate: ProbePort = ProbePort.inactive

    /** 【logfix1 任务 C 段】探测重试计数（键 `srun_probe_attempt_v1`；null = 不记账）。 */
    var probeAttempts: ProbeAttemptStore? = null

    /** 【logfix1 任务 B 段】日志写入用的 Android Context（null = 不写应用内日志，纯 JVM 场景）。 */
    var logContext: android.content.Context? = null

    /** 【logfix1 任务 C 段 / B 段】一次性装配探测与日志依赖（构造后调用；返回自身便于链式书写）。 */
    fun withProbeAndLog(
        probeGate: ProbePort,
        probeAttempts: ProbeAttemptStore?,
        logContext: android.content.Context?
    ): AuthFlow {
        this.probeGate = probeGate
        this.probeAttempts = probeAttempts
        this.logContext = logContext
        return this
    }

    /** 记录最近一次结果（供状态显示区读取；失败不静默）。 */
    var lastResult: AuthResult? = null
        private set

    var lastAttemptAtMillis: Long = 0L
        private set

    var lastOutcome: AuthFlowOutcome? = null
        private set

    /** 【logfix1 任务 B 段】上一次记录的 SSID（仅用于「检测到网络变化」这一条日志，不参与任何判定）。 */
    private var lastLoggedSsid: String? = "<首次运行>"

    /**
     * 【logfix1 任务 C 段】最近一次探测的记账状态（供调度层写「探测第几次」的日志）。
     * 仅当装配了 [probeAttempts] 且真的探测过时非 null；不参与任何判定。
     */
    val lastProbeState: ProbeAttemptState? get() = lastProbe

    /** 最近一次探测的进度（内部字段，由探测分支写入）。 */
    private var lastProbe: ProbeAttemptState? = null

    /**
     * 执行一次自动认证。
     *
     * @param targetSsid 目标 SSID（通常是用户在配置界面选定的 WiFi）。
     *                   为 null/空时退化为「以当前 SSID 为准」（用户手动点「立即登录」的场景）。
     */
    fun run(targetSsid: String?): AuthFlowOutcome {
        val started = clock()
        val current = wifiSnapshot.currentSsid()
        // 【logfix1 任务 B 段·网络检测埋点 2】SSID 读取结果（读到什么 / 为什么读不到），
        // 并顺带标记「检测到网络变化」（相邻两次读到的 SSID 不同）。
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
            ?: run {
                log("网络检测：当前 WiFi「$current」没有匹配到任何已存储的网络（未绑定账号）→ 跳过登录")
                return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_NOT_BOUND, current, targetSsid)
            }
        log("网络检测：当前 WiFi「$current」与已存储网络**匹配**（账号 label=「$boundLabel」）")

        // 步骤 3（B8 核心）：目标 SSID 与当前 SSID 必须一致，否则零请求返回
        val effectiveTarget = if (targetSsid.isNullOrBlank()) current else targetSsid.trim()
        if (current.trim() != effectiveTarget) {
            log("网络检测：当前 WiFi「$current」与目标 WiFi「$effectiveTarget」**不匹配** → 跳过登录")
            return AuthFlowOutcome.Skipped(AuthSkipReason.SSID_MISMATCH, current, effectiveTarget)
        }

        // 步骤 4：取凭据（缺失 → 结构化失败，仍然不发请求）
        val credential = credentials.find(boundLabel) ?: credentials.selected()
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

        // 步骤 5（logfix1 任务 C 段：第 ②③ 段判断）：
        //   ② 验证该网络是否为 SRun 认证系统；③ 检查是否已登录。**一次探测同时得到两个答案**。
        //   结论四种（见 ProbeOutcome）：
        //     NOT_SRUN → 跳过；ALREADY_ONLINE → 跳过；NOT_LOGGED_IN → 继续第 ④ 段；
        //     INDETERMINATE → 【probefix1 任务 B 段】**降级为继续第 ④ 段认证**（不再是「跳过并重试」）。
        // 代价：本步是**新增的一次 HTTP GET**（get_challenge）。它只在「已绑定 + 已勾选 + SSID 匹配」时才发生，
        // 每次运行最多一次。
        if (probeGate !== ProbePort.inactive) {
            val probe = probeGate.probe(portalProvider.portal(), credential.username, "")
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
                    // 【probefix1 任务 B 段】不确定 → **倾向于尝试认证**（用户口径）：
                    // 探测只是**优化**（省掉不必要的认证请求）；若探测本身不可靠（超时 / 被校园网
                    // 网关限速 / 响应形态异常），**不应该阻止真正的登录**。已在线也无害：
                    // 服务端会回「already online」，由任务 A 段的识别兜住。
                    // 「5 分钟重试、最多 2 次」通道：**不再需要**（见 fix-report.md 的判断），
                    // 因此这里**复位**计数而不是 record —— 否则历史遗留的「不确定次数」会在
                    // ProbeRetryCoordinator.beforeProbe 里把后续认证永久闸掉。
                    probeAttempts?.reset(current)
                    lastProbe = null
                    log(
                        "网络检测：WiFi「$current」探测**不确定**（依据：${probe.evidence}）" +
                            "→ **降级为继续执行认证**（探测只是优化，不应阻止登录；5 分钟重试通道不再使用）"
                    )
                }
                ProbeOutcome.NOT_LOGGED_IN -> {
                    probeAttempts?.reset(current)
                    // 【onlinefix1 任务 C 段】措辞去断言：get_challenge **对任何会话都会返回 challenge**
                    //（它是认证第一步，不代表登录状态），因此探测结论只能说「**未检测到已登录状态**」，
                    // 不能说「未登录」。真机反例（用户日志）逐字：
                    //   探测：「…是 SRun 系统且**未登录**（依据：服务端返回 challenge（长度 64）→ 当前未登录）」
                    //   紧接着认证：「服务端返回**已在线**（code=E2620）」
                    // ——同一秒内两次结论相反，说明前者是**武断断言**。真正的登录状态只有第二步
                    // `srun_portal` 才知道（由 probeGate 之后的第 6 步覆盖）。
                    log("网络检测：WiFi「$current」未检测到已登录状态，将尝试认证（依据：${probe.evidence}，账号 $safeUser）")
                }
            }
        }

        // 步骤 6：调认证客户端（唯一发认证请求的地方）
        val request = AuthRequest(
            username = credential.username,
            password = credential.password,
            acId = credential.acId,   // 已冻结：字符串 "5"
            portal = portalProvider.portal(),
            ipOverride = ""           // 空 = 由认证客户端按 client_ip → 本机探测 的顺序决定（绝不硬编码）
        )
        log("登录执行：开始认证（目标 WiFi「$current」，账号 ${AppLog.maskAccount(credential.username)}，门户 ${portalProvider.portal()}）")
        val result = transport.execute(request)
        if (result.ok) {
            log("登录执行：成功（服务端 error=${SrunProtocol.OK}，阶段 ${result.stage}，耗时 ${result.elapsedMs}ms，ip 来源 ${result.ipSource}）")
        } else {
            // 【probefix1 任务 A 段】认证路径的「已在线」识别。用户逐字指示：
            // 「"You are already online"即代表当前网络已经在线,无需登录」。
            // 真机实测：服务端对「已登录的网络再登录」返回 code=E2620、
            // msg="E2620: You are already online."，旧代码把它落成
            // AuthFailure.REJECTED（界面显示「服务端拒绝（密码错误等）」）并**消耗退避预算重试**。
            // 判定**复用探测路径的同一份正则**（[SrunProbeClassifier.isAlreadyOnline]，不复制第二份），
            // 只匹配「已在线」语义：`E2553 密码错误` 之类不会被误判（判定表见 fix-report.md）。
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

    /**
     * 写一行应用内日志（logfix1 任务 B 段）。
     *
     * 硬性要求：**日志失败绝不影响主流程** —— 本方法把写入包在 runCatching 里，
     * 且 [AppLog.record] 自身也吞异常；logContext 为 null（离线核对）时直接跳过。
     * 另外**绝不传密码**：本方法只接受已经由调用点脱敏过的文本。
     */
    private fun log(line: String) {
        val ctx = logContext ?: return
        runCatching { AppLog.record(top.ytu.srunautologin.platform.SrunStorage.keyValueStore(ctx), line) }
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

/** 认证客户端工厂接口：让「立即登录」与后台调度复用同一套装配，
 * 同时保持 flow 模块对 auth 模块实现的弱耦合（测试可注入假 transport）。
 *
 * 【logfix1 任务 C 段】`create` 保持**无参签名不变**（既有真机装配点与离线核对快照的 ABI 不受影响）；
 * 探测端口不经过本接口，而是直接装配给 [AuthFlow.probeGate]（见真机装配点
 * `AndroidAuthRunEnv.buildRun` 与 `MainActivity.buildAuthFlow`）。
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
