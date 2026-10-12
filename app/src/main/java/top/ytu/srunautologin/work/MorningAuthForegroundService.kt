package top.ytu.srunautologin.work

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import top.ytu.srunautologin.R
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.storage.AccountStore
import top.ytu.srunautologin.storage.WifiAccountMap

/**
 * ============================ 前台服务：常驻通知（未验证部分）============================
 * 用户要求：「应用在后台待机时向用户推送常驻通知」——
 *   标题：自动连接正在工作
 *   内容：已保存登录账号:<保存的登录账号名>,将登录网络:<保存的网络名称>
 * （英文半角逗号，占位符替换为真实值）
 *
 * 【本服务只做「常驻通知 + 存活」，**不做认证**】
 *  认证仍由 [AuthJobService]（JobScheduler）执行。理由：
 *   1. 认证是秒级任务，而前台服务会一直占着「前台」状态；把长连接/长任务塞进前台服务会
 *      让系统对进程施加更强的资源限制（也更容易被 OEM ROM 判为「常驻耗电」而清理）；
 *   2. 常驻通知要的是「一直可看见」而不是「一直跑网络」，两者生命周期本来就不同；
 *   3. 认证失败重试由闹钟链路（[MorningAuthRuntime]）驱动，前台服务不需要知道认证细节。
 *
 * 【前台服务类型的选择依据（API 34+ 强制声明类型 + 对应权限）】
 *  选 `dataSync`（[ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC]，常量值 0x00000001）：
 *   - 业务语义：本服务的存在意义是让「每天 6:00 的自动登录同步」在后台稳定进行，
 *     用户看得到进度 —— 属于与服务器同步数据（dataSync）的典型场景；
 *   - 为什么不用 `specialUse`：specialUse 是「确实无法归入其它类型」时用的逃生口，
 *     需要在 manifest 里用 `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE">`
 *     声明子类型（本机无法验证该 property 在 targetSdk 36 下的具体校验行为），且 Google Play
 *     对 specialUse 的审核更严（要求人工说明为什么不用标准类型）。本应用完全可以用标准类型，
 *     因此**不用 specialUse**；
 *   - 为什么不用 `shortService`：`shortService` 有约 3 分钟的运行上限，超时会被系统停止 ——
 *     与「待机时常驻通知」的要求直接冲突；
 *   - Google Play 政策含义：dataSync 是标准类型，不需要额外声明；Play 会按类型检查
 *     「声明用途与实际行为是否一致」，本服务确实不采集用户数据、不做后台定位，
 *     仅显示一条与自动登录相关的通知。
 *  权限声明在 AndroidManifest（`FOREGROUND_SERVICE` 通用权限 + `FOREGROUND_SERVICE_DATA_SYNC` 类型权限）。
 * ==========================================================================================
 */
class MorningAuthForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val ctx = applicationContext
        try {
            val notification = buildNotification(ctx)
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            AuthWorkWiring.progress(ctx, "前台服务：常驻通知已显示（${notificationTitle(ctx)} / 动态内容）")
        } catch (e: Throwable) {
            // 通知被系统禁用（API 33+ 未授予 POST_NOTIFICATIONS）或前台服务被限制：降级为「不显示」，
            // 但**必须落盘**，界面据此提示用户「通知被禁用」。
            AuthWorkWiring.progress(ctx, "前台服务：常驻通知启动失败（${e.javaClass.simpleName}）：${e.message}")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        AuthWorkWiring.progress(applicationContext, "前台服务：已停止（常驻通知随之移除）")
        super.onDestroy()
    }

    /** 通知渠道（API 26+ 必须建渠道；渠道名「自动连接」）。重复创建是幂等的。 */
    private fun ensureChannel(ctx: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            ctx.getString(R.string.morning_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = ctx.getString(R.string.morning_channel_desc)
            setShowBadge(false)
            enableVibration(false)
            setSound(null, null)
        }
        nm.createNotificationChannel(channel)
    }

    /** 构造常驻通知：标题与内容**逐字**对应用户要求；点通知回到配置界面。 */
    private fun buildNotification(ctx: Context): Notification {
        ensureChannel(ctx)
        val contentIntent = packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            var f = PendingIntent.FLAG_UPDATE_CURRENT
            if (Build.VERSION.SDK_INT >= 23) f = f or PendingIntent.FLAG_IMMUTABLE
            PendingIntent.getActivity(ctx, NOTIFICATION_ID, launch, f)
        }

        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(ctx, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(ctx)
        }
        @Suppress("DEPRECATION")
        builder
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(notificationTitle(ctx))
            .setContentText(notificationText(ctx))
            .setOngoing(true)          // 不可消除
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)    // 刷新时不重复提醒
            .setShowWhen(false)
            .setPriority(Notification.PRIORITY_LOW)
            .setVisibility(Notification.VISIBILITY_SECRET)
        // 静默刷新（用户要求：待机常驻，不要每次都响/震）。
        // 用 setSound(null) + setVibrate(null) 而不是 setSilent(true)：后者的可用性在本机 android.jar 上
        // 未被编译器解析（e: Unresolved reference 'setSilent'），而「只提醒一次 + 无声音无振动」的语义等价实现更稳。
        builder.setOnlyAlertOnce(true)
        @Suppress("DEPRECATION")
        builder.setSound(null)
        @Suppress("DEPRECATION")
        builder.setVibrate(null)
        if (contentIntent != null) builder.setContentIntent(contentIntent)
        return builder.build()
    }

    /** 通知标题：逐字对应用户要求。 */
    private fun notificationTitle(ctx: Context): String = ctx.getString(R.string.morning_notification_title)

    /**
     * 通知内容：`已保存登录账号:<保存的登录账号名>,将登录网络:<保存的网络名称>`（英文半角逗号）。
     *
     * 取值为**真实数据**：账号名 = 已保存凭据的 label（备注名，不含手机号/密码）；
     * 网络名 = 与该账号绑定的 WiFi SSID（未绑定时给出「尚未绑定」占位，绝不显示空白）。
     */
    private fun notificationText(ctx: Context): String {
        val account = savedAccountName(ctx)
        val ssid = boundSsidOf(ctx, account)
        return ctx.getString(R.string.morning_notification_text, account, ssid)
    }

    /**
     * 已保存的登录账号名（备注名）：**accountsel1（C 段）起改读 v2 账号列表**——
     * 优先「当前选中」的账号，其次第一条；一条都没有时给占位文案。
     *
     * 为什么改：v2 是当前读路径，且这里有「勾选」概念——若仍读 v1（`credentials_v1`），
     * 会出现「通知里显示着一个已被用户取消勾选/已删除的账号」这种与事实不符的显示。
     *
     * 通知里**只允许出现备注名**（label）：账号/密码一律不进通知、不进日志（D 段自查项）。
     */
    private fun savedAccountName(ctx: Context): String {
        val store = SrunStorage.accountStore(ctx)
        val accounts = store.list()
        val picked = store.selectedLabel()?.let { sel -> accounts.firstOrNull { it.label == sel } }
            ?: accounts.firstOrNull()
        return picked?.label?.takeIf { it.isNotBlank() }
            ?: ctx.getString(R.string.morning_notification_no_account)
    }

    /** 与该账号绑定的网络名：绑定表里 label 对应的 SSID；未绑定时给占位文案。 */
    private fun boundSsidOf(ctx: Context, account: String): String {
        val map = WifiAccountMap(SrunStorage.keyValueStore(ctx))
        val bound = map.mapping().entries.firstOrNull { it.value == account }?.key
        return bound?.takeIf { it.isNotBlank() }
            ?: map.mapping().keys.firstOrNull()?.takeIf { it.isNotBlank() }
            ?: ctx.getString(R.string.morning_notification_no_ssid)
    }

    companion object {
        /** 通知 ID（固定值 → 刷新同一条通知，不会堆积）。 */
        const val NOTIFICATION_ID = 0x5A21

        /** 通知渠道 ID。 */
        const val CHANNEL_ID = "srun_auto_login_channel"

        /**
         * 启动前台服务（**唯一入口**，供界面开关调用；App.onCreate 只在开关已启用时才调它）。
         * 返回 false 表示启动请求被系统拒绝（例如 Android 12+ 的后台启动前台服务限制），调用方据此提示用户。
         */
        fun Context.startMorningNotificationService(): Boolean = try {
            applicationContext.startForegroundService(
                Intent(applicationContext, MorningAuthForegroundService::class.java)
            )
            true
        } catch (e: Throwable) {
            AuthWorkWiring.progress(this, "前台服务：启动被拒（${e.javaClass.simpleName}）：${e.message}")
            false
        }

        /** 停止前台服务（用户停用开关时调用）。 */
        fun Context.stopMorningNotificationService() {
            try {
                applicationContext.stopService(
                    Intent(applicationContext, MorningAuthForegroundService::class.java)
                )
            } catch (e: Throwable) {
                AuthWorkWiring.progress(this, "前台服务：停止失败（${e.javaClass.simpleName}）：${e.message}")
            }
        }
    }
}
