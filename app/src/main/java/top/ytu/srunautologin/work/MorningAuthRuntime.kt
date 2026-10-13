package top.ytu.srunautologin.work

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import top.ytu.srunautologin.platform.SrunStorage

/**
 * ============================ Android 边界层：精确定时通道（未验证部分）============================
 * 本文件引用 Android SDK（AlarmManager / ConnectivityManager），本机**无 Android 运行时**，
 * 无法离线执行；本机唯一的编译验证是 tools/build-local.ps1 的 assembleDebug。
 * 其中所有可判定的逻辑（6:00/7:00、+10 分钟、7 次上限、每天重置）都在纯逻辑文件
 * [MorningAutoLogin] / [MorningAutoLoginPolicy] 里，可在 JVM 上复核。
 * ==================================================================================================
 *
 * 【removemorning1（用户要求）：06:00 早上例程已整体退役】
 *   用户原话：「关闭开机广播的触发通道，取消每天早上 6:00 的状态机和任务闹钟以及相应提示文本」。
 *   因此本类**不再排 06:00 闹钟**：三个 06:00 排期入口（首次 / 触发后重排下一天 / +10 分钟重试）
 *   已全部删除（它们是唯一能排 06:00 与 +10 分钟闹钟的地方）；
 *   [MorningAlarmReceiver] 也**不再执行早上例程**，只服务「探测不确定 → 5 分钟重试」这条闹钟通道
 *   （logfix1 任务 C 段，由 [AuthWorkWiring] 的周期任务排期 —— 与本任务无关，按用户要求保留）。
 * 【为什么闹钟通道仍然保留 AlarmManager】探测重试用的是同一条精确闹钟通道（5 分钟）。
 *   JobScheduler 的周期任务在 Doze/待机分组下会被推迟（15 分钟周期保底仍然保留，是另一条通道），
 *   只有 `setExactAndAllowWhileIdle` 能在 Doze 下被系统唤醒执行。
 * 【保留但不再被调用的纯逻辑】6:00/7:00 窗口、每天 7 次上限、计数存储
 *   （[MorningAutoLogin] / [MorningAutoLoginPolicy] / [MorningStateStore]）原样保留，
 *   但已经没有任何调度入口调用它们（供将来需要时复用，同时避免大范围删除带来的回归面）。
 */
object MorningAuthRuntime {

    /** 互斥门：早上例程同一时刻只允许一个执行体（进程内）。 */
    val LOCK: Any = Any()

    @Volatile
    private var running: Boolean = false

    /** 早上例程是否正在执行（供周期兜底让路、供排障日志读取）。 */
    fun isRunning(): Boolean = running

    /** 进入/退出执行区（配对使用；异常路径也必须退出）。 */
    fun markRunning(value: Boolean) {
        running = value
    }

    /**
     * 「早上例程刚跑过」的让路窗口（毫秒）：**小于重试间隔 10 分钟**，
     * 保证不会吃掉真正的下一次重试。
     */
    const val MORNING_IN_FLIGHT_WINDOW_MS: Long = 5 * 60_000L

    /** 距上一次早上尝试是否不足 [MORNING_IN_FLIGHT_WINDOW_MS]（周期兜底用）。 */
    fun isMorningAttemptInFlight(context: Context, nowMillis: Long): Boolean {
        val last = MorningStateStore(SrunStorage.keyValueStore(context.applicationContext))
            .loadToday(nowMillis).lastAtMillis
        return last > 0L && nowMillis - last < MORNING_IN_FLIGHT_WINDOW_MS
    }

    // removemorning1：原启停开关的读写（isEnabled / setEnabled）已删除 ——
    // 开关的**唯一**界面入口（morning1 的「点击切换自动登录状态」按钮）按用户要求移除，
    // 而它的默认值是停用（MorningStateStore.DEFAULT_ENABLED = false）；
    // 若保留任何闸门判断，会让「必须保留」的周期保底与网络变化通道在默认配置下全部失效。
    // 存储键不再被读写，历史值成为惰性数据（不影响任何行为）。

    /* ------------------------------------------------------------------ 排期 */

    /** 06:00 的 PendingIntent（同 action/requestCode → 同一实例，可覆盖、可取消）。 */
    private fun alarmIntent(context: Context, reason: String): PendingIntent {
        val intent = Intent(context.applicationContext, MorningAlarmReceiver::class.java).apply {
            action = ACTION_MORNING
            putExtra(EXTRA_REASON, reason)
        }
        var flags = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= 23) flags = flags or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getBroadcast(context.applicationContext, REQUEST_CODE, intent, flags)
    }

    /** 系统是否允许精确闹钟（API 31+ 需要「闹钟与提醒」特殊权限；31 以下一律允许）。 */
    fun canScheduleExact(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 31) return true
        val am = context.applicationContext.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return false
        return try {
            am.canScheduleExactAlarms()
        } catch (e: Throwable) {
            false
        }
    }

    // removemorning1：三个「06:00 / +10 分钟」排期入口已删除（用户要求取消每天早上 6:00 的
    // 定时任务）：三个入口分别是首次 06:00、触发后重排下一天、+10 分钟重试。
    // 删除它们是「不再有 06:00 闹钟」的**结构性**保证：
    // 全工程已不存在调用 AlarmManager 排 06:00 的代码路径。
    /**
     * 【logfix1 任务 C 段：探测重试通道】安排一次「探测不确定」的重试闹钟。
     *
     * 用户决策：探测不确定 → 等 **5 分钟**重试，最多 **2 次**（共 3 次探测），全败记日志、不再尝试。
     *
     * 为什么复用本类的闹钟而不新开一套：既有的 [MorningAlarmReceiver] 已经是「时间到了就在后台
     * 线程跑一段判定链」的成熟通道（goAsync + 后台线程 + 探测闸门），
     * 探测重试与它**同类**；新开一条通道只会让「到底有几套重试在跑」变得不可读。
     * （removemorning1：原先提到的「开关守卫 / 让路窗口」已随早上任务一起删除。）
     * 本方法只改变**触发时刻**（5 分钟 vs 10 分钟），触发后的判定链完全同一条。
     */
    fun scheduleProbeRetry(context: Context, atMillis: Long): Long {
        val ctx = context.applicationContext
        fire(ctx, atMillis, "retry-probe-5min")
        AuthWorkWiring.progress(
            ctx,
            "网络检测：安排探测重试（${AuthStatusStore.formatTime(atMillis)}，间隔 " +
                "${top.ytu.srunautologin.flow.ProbeRetryPolicy.RETRY_DELAY_MS / 60_000} 分钟）"
        )
        return atMillis
    }

    /** 真正落一次闹钟（两个 API 分支都返回；异常不吞、由调用方 try/catch 兜住）。 */
    private fun fire(context: Context, atMillis: Long, reason: String) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val pi = alarmIntent(context, reason)
        if (canScheduleExact(context)) {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, atMillis, pi)
        } else {
            // 降级：允许在 Doze 下唤醒，但**不保证精确**（系统可能推迟几分钟）。
            // 明确记录日志，用户排障时能看到「为什么不准时」。
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, atMillis, pi)
            AuthWorkWiring.progress(
                context,
                "早上例程：无法精确调度（SCHEDULE_EXACT_ALARM 未授权）→ 降级 setAndAllowWhileIdle，时刻可能被系统推迟"
            )
        }
    }

    /** 取消全部早上闹钟（用户停用开关时调用）。 */
    fun cancel(context: Context) {
        val ctx = context.applicationContext
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        runCatching { am.cancel(alarmIntent(ctx, "cancel")) }
        AuthWorkWiring.keyValueStore(ctx).putString(KEY_SCHEDULED_FIRST, "")
    }

    /** 最近一次排定的 06:00 时刻（界面/排障展示用）。 */
    fun scheduledFirst(context: Context): Long =
        AuthWorkWiring.keyValueStore(context.applicationContext).getString(KEY_SCHEDULED_FIRST)?.toLongOrNull() ?: 0L

    private fun setScheduledFirst(context: Context, atMillis: Long) {
        AuthWorkWiring.keyValueStore(context).putString(KEY_SCHEDULED_FIRST, atMillis.toString())
    }

    /**
     * 「已处于在线状态」的**轻量探测**（A4）：只看系统给的 [NetworkCapabilities]，**不发 Portal 请求**。
     *
     * 采用 `NET_CAPABILITY_INTERNET` 而不是 `NET_CAPABILITY_VALIDATED`：
     *  - VALIDATED 需要系统真的对互联网做过一次探测才置位；在 Captive Portal（校园网未认证）场景里
     *    两种能力都可能不置位，用 INTERNET 语义更清晰（「这条网络声称能上互联网」）；
     *  - 与既有 [NetworkWatcher.isOnWifi] 的口径保持一致（同一判据，避免两套标准）。
     * 返回 null 表示**探测不确定**（读不到网络能力）→ 调用方按「不确定 → 倾向于尝试认证」处理。
     */
    fun isCurrentlyOnline(context: Context): Boolean? {
        val cm = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return null
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return null
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    const val ACTION_MORNING = "top.ytu.srunautologin.action.MORNING_AUTH"

    /**
     * 探测重试闹钟的 reason 前缀：`scheduleProbeRetry` 用它作为触发来源标记，
     * [MorningAlarmReceiver] 据此把「探测重试」与「已退役的早上例程（06:00）」区分开。
     */
    const val REASON_PROBE_RETRY_PREFIX = "retry-probe"

    /** 闹钟 PendingIntent 的请求码（与其它 PendingIntent 不冲突）。 */
    const val REQUEST_CODE = 0x5A11

    const val EXTRA_REASON = "morning_reason"

    /** 最近一次排定的 06:00 的存储键。 */
    const val KEY_SCHEDULED_FIRST = "srun_morning_scheduled_first_v1"
}

/**
 * 【触发点：探测不确定 → 5 分钟重试】AlarmManager 回调。
 *
 * removemorning1：早上 06:00 首次 + 每 10 分钟重试的早上例程**已按用户要求取消**，
 * 本接收者现在**只服务**「探测不确定」这条重试通道（见 [ProbeRetryCoordinator]）。
 *
 * 为什么这里用 goAsync() 而不是直接同步跑认证：
 *  认证是阻塞 IO（可能几十秒），而 AlarmManager 投递的广播跑在**主线程**；
 *  goAsync() 给 10 秒预算，足够完成「轻量在线探测 + 闸门判定 + 排期」，
 *  真正的认证请求交给既有 [AuthJobService]（后台线程、可长时间执行）。
 */
class MorningAlarmReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        val ctx = context?.applicationContext ?: return
        if (intent?.action != MorningAuthRuntime.ACTION_MORNING) return
        val reason = intent.getStringExtra(MorningAuthRuntime.EXTRA_REASON) ?: "morning"

        val pending = goAsync()
        Thread({
            try {
                handle(ctx, reason)
            } catch (e: Throwable) {
                // 任何异常都必须落盘：早上的自动登录失败了，用户要能在应用里看到原因
                AuthWorkWiring.progress(ctx, "早上例程异常：${e.javaClass.name}: ${e.message}")
            } finally {
                runCatching { pending.finish() }
            }
        }, "srun-morning-alarm").apply { isDaemon = true }.start()
    }

    /**
     * 一次「早上例程」：
     *  1. 开关停用 → 直接返回（**这条必须最先判**，见 C4 覆盖清单）；
     *  2. 不在 06:00–07:00 窗口 → 只重排下一天 06:00（避免开机后系统重投的旧闹钟误触发）；
     *  3. 已经在线 → 记一次尝试并收工（用户要求「未处于登录状态」才登录）；
     *  4. 其余 → 记一次尝试（+1，持久化）→ 交给既有认证链路 → 按结果决定是否排 +10 分钟重试。
     */
    private fun handle(ctx: Context, reason: String) {
        // 【logfix1 任务 B 段】调度埋点：闹钟（06:00 / +10 分钟重试 / 探测重试）真的被系统唤醒了
        runCatching {
            top.ytu.srunautologin.log.AppLog.record(
                top.ytu.srunautologin.platform.SrunStorage.keyValueStore(ctx),
                "调度：定时闹钟触发（reason=$reason，时刻 ${AuthStatusStore.formatTime(System.currentTimeMillis())}）"
            )
        }
        // removemorning1（用户要求「取消每天早上 6:00 的状态机和任务闹钟」）：
        // 早上例程已整体退役 —— 非探测来源的触发一律**不认证、不排期、不重排下一天**。
        // 兼容处理：升级前已排定的旧 06:00 闹钟仍可能被系统投递，走到这里直接返回即自然失效
        //（**注意**：这里绝不能重排下一天，否则会复活 06:00 闹钟）。
        if (!reason.startsWith(MorningAuthRuntime.REASON_PROBE_RETRY_PREFIX)) {
            AuthWorkWiring.progress(ctx, "定时闹钟($reason)：早上例程已退役（06:00 定时任务已取消）→ 不认证、不重排")
            return
        }

        // 轻量在线探测（A4）：已在线 → 不重复打 Portal。这是探测重试通道的唯一前置判定
        //（原「06:00–07:00 窗口 / 当天 7 次上限 / 记账」三段落已随早上任务删除）。
        val online = MorningAuthRuntime.isCurrentlyOnline(ctx)
        AuthWorkWiring.progress(ctx, "网络检测($reason)：轻量在线探测(NET_CAPABILITY_INTERNET)=$online")
        if (online == true) {
            AuthWorkWiring.progress(ctx, "网络检测($reason)：网络已具备互联网能力 → 不重复认证")
            return
        }

        // 交给既有认证链路（JobScheduler 单通道）：它内部会复用 AuthFlow 的 SSID 匹配跳过逻辑。
        // 【logfix1 任务 C 段】先过「探测重试闸门」：
        //   ① 距上次探测不足 5 分钟 → 让路（不探测、不认证）；
        //   ② 探测重试额度已用尽（3 次都不确定）→ 记日志、不再尝试。
        // 让路的判断放在**发起认证之前**，否则「闸门」会退化成事后检查，仍然会多发请求。
        val targetSsid = runCatching {
            top.ytu.srunautologin.platform.SrunStorage.wifiAccountMap(ctx).mapping().keys.firstOrNull()
        }.getOrNull()
        val probeGate = ProbeRetryCoordinator.beforeProbe(
            kv = SrunStorage.keyValueStore(ctx),
            ssid = targetSsid,
            probeEnabled = true,
            nowMillis = System.currentTimeMillis(),
            scheduleRetry = { at -> MorningAuthRuntime.scheduleProbeRetry(ctx, at) }
        )
        if (probeGate == ProbeRetryCoordinator.Action.WAIT || probeGate == ProbeRetryCoordinator.Action.GIVE_UP) {
            top.ytu.srunautologin.log.AppLog.record(
                SrunStorage.keyValueStore(ctx),
                "调度：探测重试闹钟($reason) 探测闸门=$probeGate → 本次不发起登录"
            )
            return
        }

        val enqueued = try {
            AuthWorkWiring.scheduler(ctx).enqueueAuth(
                delayMillis = 0L,
                reason = "probe-$reason"
            )
        } catch (e: Throwable) {
            AuthWorkWiring.progress(ctx, "网络检测：探测重试排期失败 ${e.javaClass.simpleName}：${e.message}")
            false
        }
        AuthWorkWiring.progress(
            ctx,
            "网络检测：探测重试($reason) 已交由认证任务排队（enqueued=$enqueued），随后按结果决定是否重试"
        )
    }
}
