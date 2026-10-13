package top.ytu.srunautologin.work

import top.ytu.srunautologin.flow.ProbeAttemptStore
import top.ytu.srunautologin.flow.ProbeOutcome
import top.ytu.srunautologin.flow.ProbeRetryPolicy
import top.ytu.srunautologin.log.AppLog
import top.ytu.srunautologin.storage.KeyValueStore

/**
 * ============================ 探测重试的**唯一**排期口（logfix1 任务 C 段）============================
 *
 * 用户要求（原话确认的决策）：探测**不确定**（超时/无响应）时 → **等 5 分钟重试，最多 2 次重试**
 * （即最多 3 次尝试）；**全部失败 → 记日志、不再尝试**（不无限重试）。
 *
 * 【本文件为什么是纯逻辑（零 `import android.`）】既有离线核对有一套不变式（W42）：
 * work 包里的纯逻辑文件必须能在无 Android SDK 的机器上编译 —— 因此本类只接受
 * [KeyValueStore]（storage 层的纯 JVM 接口）与一个「写一行日志」的闭包，不引用 Context。
 * 真机调用点（[MorningAuthRuntime] / [AuthWorkWiring]，都是 Android 边界层）负责把它们传进来。
 *
 * 【为什么单独一个类】本机有三套「重试」：既有 [RetryPolicy]（认证失败，最多 5 次、延迟由服务端给）、
 * 早上 6:00 的 7 次重试（[MorningAutoLoginPolicy]，到 07:00）、以及本任务新增的探测重试。
 * 三者若各自为政就会叠加成「双重无限重试」。因此这里把探测重试的**计数、间隔、上限、排期**
 * 全部收进一处：
 *
 *  - **计数**：`srun_probe_attempt_v1`（[ProbeAttemptStore]，与认证的 `srun_auth_*`、早上的
 *    `srun_morning_attempts_v1` **完全不同的键**，互不干扰）；
 *  - **间隔**：5 分钟（[ProbeRetryPolicy.RETRY_DELAY_MS]）；
 *  - **上限**：2 次重试（共 3 次探测）；
 *  - **排期**：[scheduleRetry] 回调（真机 = [MorningAuthRuntime.scheduleProbeRetry] 的闹钟）；
 *    每次触发 = 一次探测，**不在同一次运行里 sleep 5 分钟**（那样会占用 JobScheduler 的执行预算，
 *    且本机无法验证）；
 *  - **互斥**：只要本协调器给出 [Action.RETRY] / [Action.WAIT] / [Action.GIVE_UP]，调用方就**必须直接返回**，
 *    **绝不能**再交给认证链路 —— 这是「不叠加」的关键（探测不确定时一个认证请求都不发）。
 *
 * 【与既有两条重试通道的关系】探测不确定时 AuthFlow 返回 `E_SKIP_PROBE_UNCERTAIN`
 * （前缀 `E_SKIP_` = 零请求跳过），因此：
 *  - [BackoffScheduler] 把它当「零请求跳过」→ **不消耗** 5 次退避预算、不触发指数退避；
 *  - 早上例程的 7 次/天计数只由它自己在 [MorningStateStore] 记账，本协调器不写那个键。
 *  完整状态机图见 artifacts/logfix1/fix-report.md（C 段）。
 */
object ProbeRetryCoordinator {

    /** 一次判定的结论。 */
    enum class Action {
        /** 不启用探测（或 SSID 为空）→ 调用方按原逻辑继续（探测在 AuthFlow 里做）。 */
        NONE,

        /** 距上次探测不足 5 分钟 → **不探测、不认证**，直接返回（下一次触发会再试）。 */
        WAIT,

        /** 不确定后仍有重试额度 → 已排下一次探测：**不认证**，直接返回。 */
        RETRY,

        /** 重试额度用尽（3 次探测都不确定）→ 记日志、**不再尝试**：不认证，直接返回。 */
        GIVE_UP
    }

    /**
     * 入口闸门（必须在「真正探测/认证之前」调用，且所有后台入口都调用它）。
     *
     * @param kv           键值存储（真机 = `SrunStorage.keyValueStore(appContext)`）
     * @param ssid         当前 SSID（本轮候选目标）；为空 → [Action.NONE]
     * @param probeEnabled 是否启用探测链路（false → [Action.NONE]，行为与改造前一致）
     * @param scheduleRetry 排下一次探测的副作用（真机 = `MorningAuthRuntime.scheduleProbeRetry`）
     */
    fun beforeProbe(
        kv: KeyValueStore,
        ssid: String?,
        probeEnabled: Boolean,
        nowMillis: Long = System.currentTimeMillis(),
        scheduleRetry: ((Long) -> Unit)? = null
    ): Action {
        if (!probeEnabled || ssid.isNullOrBlank()) return Action.NONE
        val store = ProbeAttemptStore(kv)
        val state = store.loadFor(ssid)
        val decision = ProbeRetryPolicy.canProbe(state, nowMillis)
        if (decision.canRetry) {
            // 还没探测过、或已过 5 分钟：允许这一次探测（探测动作在 AuthFlow 内）
            return Action.NONE
        }
        if (state.attempts >= ProbeRetryPolicy.MAX_ATTEMPTS) {
            log(
                kv,
                "网络检测：「$ssid」探测已连续 ${state.attempts} 次不确定（上限 ${ProbeRetryPolicy.MAX_ATTEMPTS} 次）" +
                    "→ 记日志后不再尝试（等网络变化或用户手动点「立即登录」重新开始）"
            )
            return Action.GIVE_UP
        }
        log(kv, "网络检测：「$ssid」${decision.reason} → 本次不探测、不登录")
        return Action.WAIT
    }

    /**
     * 探测结束后的收尾（把「不确定」翻译成重试排期）。
     *
     * 只有 [ProbeOutcome.INDETERMINATE] 时才有动作；其它三种确定结论由 AuthFlow 处理
     * （它已复位计数、并按结论跳过或进入登录）。
     */
    fun afterProbe(
        kv: KeyValueStore,
        ssid: String?,
        outcome: ProbeOutcome?,
        nowMillis: Long = System.currentTimeMillis(),
        scheduleRetry: ((Long) -> Unit)? = null
    ): Action {
        if (ssid.isNullOrBlank() || outcome != ProbeOutcome.INDETERMINATE) return Action.NONE
        val store = ProbeAttemptStore(kv)
        val state = store.loadFor(ssid)
        if (state.attempts >= ProbeRetryPolicy.MAX_ATTEMPTS) {
            log(
                kv,
                "网络检测：「$ssid」探测不确定已达 ${ProbeRetryPolicy.MAX_ATTEMPTS} 次" +
                    "（1 次首次 + ${ProbeRetryPolicy.MAX_RETRIES} 次重试）→ 记日志后不再尝试"
            )
            return Action.GIVE_UP
        }
        val at = ProbeRetryPolicy.nextRetryAtMillis(nowMillis)
        runCatching { scheduleRetry?.invoke(at) }
        log(
            kv,
            "网络检测：「$ssid」探测不确定（第 ${state.attempts} 次）→ 已安排在 " +
                "${AuthStatusStore.formatTime(at)} 重试（第 ${state.attempts + 1} 次探测，" +
                "${ProbeRetryPolicy.describe()}）；本次不发起登录"
        )
        return Action.RETRY
    }

    /** 复位探测计数（换网络 / 用户手动点「立即登录」/ 探测出确定结论时调用）。 */
    fun reset(kv: KeyValueStore, ssid: String?) {
        if (ssid.isNullOrBlank()) return
        runCatching { ProbeAttemptStore(kv).reset(ssid) }
    }

    private fun log(kv: KeyValueStore, line: String) {
        runCatching { AppLog.record(kv, line) }
    }
}
