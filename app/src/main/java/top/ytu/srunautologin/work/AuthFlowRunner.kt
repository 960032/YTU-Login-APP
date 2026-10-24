package top.ytu.srunautologin.work

import top.ytu.srunautologin.auth.AuthFailure
import top.ytu.srunautologin.auth.AuthRequest
import top.ytu.srunautologin.auth.AuthResult
import top.ytu.srunautologin.auth.AuthStage
import top.ytu.srunautologin.auth.AuthTransport
import top.ytu.srunautologin.flow.AuthFlow
import top.ytu.srunautologin.flow.AuthFlowOutcome
import top.ytu.srunautologin.flow.CredentialLookup

/**
 * 运行环境缝（模块 work，纯 JVM）。
 *
 * 存在的唯一目的：让「读当前 SSID → 组装一次认证运行」这段**编排代码本身**可以在
 * JVM 上离线执行（见 artifacts/android-ci/offline-check/WorkOfflineCheck.kt），
 * 从而把「零 SSID 判断」这条 B8 纪律变成可验证的事实，而不是口头声明。
 *
 * 真机由 [AuthWorkWiring] 提供实现（Android Context + storage/net/auth 模块）。
 */
interface AuthRunEnv {
    /** 当前连接的 WiFi SSID；读不到返回 null（等价 AuthFlow 的 E_SKIP_NO_SSID 前置条件）。 */
    fun currentSsid(): String?

    /**
     * 构建一次认证运行。
     * @param minRetryIntervalSeconds 周期任务去抖间隔；0 = 不限制（手动触发）
     */
    fun buildRun(trigger: TriggerKind, minRetryIntervalSeconds: Long): AuthRun
}

/** 一次可执行的认证运行（[coordinator] 与 [targetSsid] 一起构成完整输入）。 */
data class AuthRun(val coordinator: AuthWorkCoordinator, val targetSsid: String?)

/**
 * 后台认证的**执行编排**（纯 JVM）。
 *
 * 四条纪律（与基准卡逐条对应）：
 *  1. 目标 SSID 的**选择**只从「用户已绑定的 SSID 集合」里取（[AuthRunEnv] 提供），
 *     本函数**不做任何匹配/比较**——匹配与否由 [AuthFlow] 的 B8 逻辑决定；
 *  2. 无论目标取到什么，都交给 [AuthFlow.run]，由它输出 `E_SKIP_*`（零请求）或真实结果；
 *  3. 调用次数上限 1：本函数只调用一次 [AuthWorkCoordinator.run]；
 *  4. 结果全部经 [AuthStatusStore] 落盘（B5）。
 */
object AuthFlowRunner {

    /**
     * @param configuredTarget 用户在配置界面绑定的目标 SSID（可为 null）
     * @param boundSsids       用户已绑定的全部 SSID（来自 WifiAccountMap；用于判断当前网络是否已绑定，
     *                         **仅作选择，不作判定**）
     */
    fun runWithTargetSelection(
        env: AuthRunEnv,
        trigger: TriggerKind,
        periodic: Boolean,
        configuredTarget: String?,
        boundSsids: List<String>,
        minRetryIntervalSeconds: Long
    ): AuthRunResult {
        val currentSsid = env.currentSsid()
        val run = env.buildRun(trigger, if (periodic) minRetryIntervalSeconds else 0L)
        return run.coordinator.run(targetOf(currentSsid, configuredTarget, boundSsids))
    }

    /**
     * 目标 SSID 的选择规则（**全函数没有比较运算符以外的判定，也不读绑定关系以外的状态**）：
     *  - 有显式配置目标 → 用它；
     *  - 否则，当前网络若在用户的绑定集合里 → 用当前网络（用户已在界面上把它绑到某账号）；
     *  - 否则用绑定集合里的任意一个 → AuthFlow 必然给出 E_SKIP_SSID_MISMATCH（零请求）。
     *
     * 之所以要「取一个」而不是传 null：null 会让 AuthFlow 退化成「以当前 SSID 为准」，
     * 那样在**任意**已绑定网络上都会自动登录，违背 B8 的「只在目标 WiFi 上认证」。
     *
     * 【本函数不是第二套 SSID 判定】它只决定「把哪个 SSID 交给 AuthFlow」；
     * 「是否发请求」由 AuthFlow 内部唯一的 B8 判据决定（flow/AuthFlow.kt:162-176）。
     */
    fun targetOf(currentSsid: String?, configuredTarget: String?, boundSsids: List<String>): String? {
        val explicit = configuredTarget?.takeIf { it.isNotEmpty() }
        if (explicit != null) return explicit
        val bound = boundSsids.filter { it.isNotBlank() }
        // 下面这一处比较只用于「在候选集合里挑选一个 SSID 作为参数」。
        // 它**不是**认证判定：返回值一律作为 targetSsid 交给 AuthFlow.run()，
        // 由 flow/AuthFlow.kt:162-176 唯一一处 B8 判据决定「发不发请求」。
        return bound.firstOrNull { it == currentSsid } ?: bound.firstOrNull()
    }

    /** 当前 SSID（读一次环境，供调度层日志/状态使用）。 */
    fun readCurrentSsid(env: AuthRunEnv): String? = env.currentSsid()

    /** 运行环境缺凭据时构造结构化结果（不调用网络、不消耗退避次数）。 */
    fun noCredentialResult(trigger: TriggerKind, atMillis: Long, maxAttempts: Int): AuthRunResult =
        AuthRunResult(
            outcome = RunOutcome.NO_CREDENTIAL,
            code = "E_CONFIG",
            message = "尚未配置任何账号，后台认证跳过（请在应用内填写账号并保存）",
            authOk = false,
            trigger = trigger,
            attempt = 0,
            attemptsConsumed = false,
            finishedAtMillis = atMillis,
            delaySeconds = 0,
            ranFlow = false,
            statusLine = AuthStatusStore.formatLine(
                trigger = trigger,
                atMillis = atMillis,
                ok = false,
                code = "E_CONFIG",
                message = "尚未配置任何账号（请先在应用内保存账号）",
                failureName = AuthFailure.CONFIG_MISSING.displayName,
                attempts = 0,
                maxAttempts = maxAttempts
            )
        )
}

