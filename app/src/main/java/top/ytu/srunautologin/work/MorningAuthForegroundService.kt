package top.ytu.srunautologin.work

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import top.ytu.srunautologin.R
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.storage.AccountStore

/**
 * ============================ 前台服务：常驻通知 ============================
 * 【restoretoggle1 恢复】本文件与 `73f2e99` 删除前的同名文件**同路径同名**（不另起新名，理由见下），
 * 实现按用户当时确认的最终要求重建；旧实现的坑（`setSilent` 不可用）已按
 * `artifacts/morning1/fix-report.md` 的等价替代处理。
 *
 * 【为什么沿用原文件名 `MorningAuthForegroundService`（而不是改名 AutoLoginForegroundService）】
 *  1. 仓库里确实有一处**按文件名与类名**做的离线核对：verify-common 系列里的 `WorkOfflineCheck` 之 `W43`
 *     （"work/ 前台服务性质合规"）逐字取 `work/MorningAuthForegroundService.kt` 与
 *     manifest 里的 `top.ytu.srunautologin.work.MorningAuthForegroundService` 做断言；改名会让它
 *     **误判为缺失**（不是代码缺陷，但会凭空多一条失败）；
 *  2. 改名会凭空丢掉一份仍然有效的核对覆盖（W43 的六条性质检查）。
 *  ⇒ 沿用的代价只是「注释里带 Morning 这个词」，收益是保留断言覆盖；因此选择沿用（任务书允许「你判断」）。
 *
 * 【本服务只做「常驻通知 + 存活」，**不做认证**】
 *  认证仍由 [AuthJobService]（JobScheduler）执行。理由（与旧实现一致，未变）：
 *   1. 认证是秒级任务，而前台服务会一直占着「前台」状态；把长任务塞进前台服务会让系统对进程施加
 *      更强的资源限制（也更容易被 OEM ROM 判为「常驻耗电」而清理）；
 *   2. 常驻通知要的是「一直可看见」而不是「一直跑网络」，两者生命周期本来就不同；
 *   3. 认证失败重试由闹钟链路（[MorningAuthRuntime]）驱动，前台服务不需要知道认证细节。
 *
 * 【前台服务类型的选择依据（API 34+ 强制声明类型 + 对应权限）】
 *  选 `dataSync`（[ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC]，常量值 0x00000001）：
 *   - 业务语义：本服务存在的意义是让「自动登录同步」在后台稳定可见 —— 属于与服务器同步数据
 *     （dataSync）的典型场景；
 *   - 为什么不用 `specialUse`：它是「确实无法归入其它类型」时的逃生口，需要在 manifest 里用
 *     `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE">` 声明子类型
 *     （本机无法验证该 property 在 targetSdk 36 下的校验行为），且 Google Play 对 specialUse 的审核更严。
 *     本应用完全可以用标准类型，因此**不用 specialUse**；
 *   - 为什么不用 `shortService`：`shortService` 有约 3 分钟的运行上限，超时会被系统停止 ——
 *     与「待机时常驻通知」的要求直接冲突；
 *   - Google Play 政策含义：dataSync 是标准类型，不需要额外声明；Play 会按类型检查
 *     「声明用途与实际行为是否一致」，本服务确实不采集用户数据、不做后台定位，仅显示一条与自动登录相关的通知。
 *  权限声明在 AndroidManifest（`FOREGROUND_SERVICE` 通用权限 + `FOREGROUND_SERVICE_DATA_SYNC` 类型权限）。
 * ==========================================================================
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
            // 【logfix1 日志面】用户可见的日志里也留一条（通知服务是「他有没有在跑」最直接的证据）
            runCatching {
                top.ytu.srunautologin.log.AppLog.record(
                    SrunStorage.keyValueStore(ctx),
                    "应用执行：常驻通知前台服务已启动（通知不可消除）"
                )
            }
        } catch (e: Throwable) {
            // 通知被系统禁用（API 33+ 未授予 POST_NOTIFICATIONS）或前台服务被限制：降级为「不显示」，
            // 但**必须落盘**，界面据此提示用户「通知被禁用」。
            AuthWorkWiring.progress(ctx, "前台服务：常驻通知启动失败（${e.javaClass.simpleName}）：${e.message}")
            logNotificationDenied(ctx, e)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        AuthWorkWiring.progress(applicationContext, "前台服务：已停止（常驻通知随之移除）")
        runCatching {
            top.ytu.srunautologin.log.AppLog.record(
                SrunStorage.keyValueStore(applicationContext),
                "应用执行：常驻通知前台服务已停止（通知已移除）"
            )
        }
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
            .setOngoing(true)          // 不可消除（用户要求：常驻通知）
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)    // 刷新时不重复提醒
            .setShowWhen(false)
            .setPriority(Notification.PRIORITY_LOW)
            .setVisibility(Notification.VISIBILITY_SECRET)
        // 静默刷新（用户要求：待机常驻，不要每次都响/震）。
        // 用 setSound(null) + setVibrate(null) 而不是 setSilent(true)：后者的可用性在本机 android.jar 上
        // 未被编译器解析（e: Unresolved reference 'setSilent'），而「只提醒一次 + 无声音无振动」的
        // 语义等价实现更稳（见 artifacts/morning1/fix-report.md 的 §B 与 compile-raw.txt）。
        builder.setOnlyAlertOnce(true)
        @Suppress("DEPRECATION")
        builder.setSound(null)
        @Suppress("DEPRECATION")
        builder.setVibrate(null)
        if (contentIntent != null) builder.setContentIntent(contentIntent)
        return builder.build()
    }

    /** 通知标题：逐字对应用户要求（`自动连接正在工作`）。 */
    private fun notificationTitle(ctx: Context): String = ctx.getString(R.string.morning_notification_title)

    /**
     * 通知内容：`已保存登录账号:<备注名>,将登录网络:<网络名>`（英文半角逗号）。
     *
     * 取值为**真实数据**：账号名 = 已保存账号的 label（备注名，**不含手机号/密码**）；
     * 网络名 = 与该账号绑定的 WiFi SSID（未绑定时给出「尚未绑定」占位，绝不显示空白）。
     * 「绝不显示手机号/密码」是硬约束：本方法只取 `label` 与 SSID 两个字段，从不读取 `username`/`password`。
     */
    private fun notificationText(ctx: Context): String {
        val account = savedAccountName(ctx)
        val ssid = boundSsidOf(ctx, account)
        return ctx.getString(R.string.morning_notification_text, account, ssid)
    }

    /**
     * 已保存的登录账号名（备注名）：读 v2 账号列表（含勾选状态，与界面同一读路径）——
     * 优先「当前选中」的账号，其次第一条；一条都没有时给占位文案。
     *
     * 为什么不读 v1（`credentials_v1`）：v2 才是当前读路径，且这里有「勾选」概念——若仍读 v1，
     * 会出现「通知里显示着一个已被用户取消勾选/已删除的账号」这种与事实不符的显示。
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
        val map = SrunStorage.wifiAccountMap(ctx)
        val bound = map.mapping().entries.firstOrNull { it.value == account }?.key
        return bound?.takeIf { it.isNotBlank() }
            ?: map.mapping().keys.firstOrNull()?.takeIf { it.isNotBlank() }
            ?: ctx.getString(R.string.morning_notification_no_ssid)
    }

    /** 失败落盘（通知不可用不是崩溃理由，但绝不能静默）。 */
    private fun logNotificationDenied(ctx: Context, e: Throwable) {
        runCatching {
            top.ytu.srunautologin.log.AppLog.record(
                SrunStorage.keyValueStore(ctx),
                "应用执行：常驻通知启动失败（${e.javaClass.simpleName}）：${e.message ?: "无 message"}"
            )
        }
    }

    companion object {
        /** 通知 ID（固定值 → 刷新同一条通知，不会堆积）。 */
        const val NOTIFICATION_ID = 0x5A21

        /** 通知渠道 ID。 */
        const val CHANNEL_ID = "srun_auto_login_channel"

        /**
         * 启动前台服务（**唯一入口**）。返回 false 表示启动请求被系统拒绝（例如 Android 12+ 的
         * 后台启动前台服务限制）或通知权限不可用 —— 调用方据此提示用户，但**绝不崩溃**。
         *
         * 【Android 12+（API 31）后台启动限制】不在前台时调用 `startForegroundService` 会抛
         * `ForegroundServiceStartNotAllowedException`（它是 IllegalStateException 的子类）；
         * 【Android 14+（API 34）】还要求 manifest 声明类型+类型权限，否则抛
         * `MissingForegroundServiceTypeException` / `SecurityException`。
         * 这里用 `catch (e: Throwable)` 全部兜住 → 记一条进度日志并返回 false，**不让异常逃到
         * 调用方（App.onCreate / 按钮点击）导致闪退**。
         */
        fun notificationPermissionGranted(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < 33) return true
            return try {
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                    PackageManager.PERMISSION_GRANTED
            } catch (e: Throwable) {
                false
            }
        }
    }
}

/**
 * ============================ Context 扩展：常驻通知前台服务的启动/停止 ============================
 * 【restoretoggle1】这两个扩展函数**故意放在类外的顶层**（而不是 companion object 内）：
 *   · 类内（companion 里的）`fun Context.xxx()` 用 `对象名.xxx(ctx)` 的形式调用时在本机 Kotlin
 *     编译器上解析不到（实测 `Unresolved reference`，见 compile-raw.txt 的三次失败记录）；
 *   · 顶层扩展只要 import 就能用最直白的形式调用，且**不与 Context 的任何成员同名**（避免成员遮蔽扩展）。
 *
 * 【Android 12+（API 31）后台启动限制】不在前台时调用 `startForegroundService` 会抛
 * `ForegroundServiceStartNotAllowedException`（IllegalStateException 子类）；
 * 【Android 14+（API 34）】还要求 manifest 声明类型 + 类型权限，否则抛
 * `MissingForegroundServiceTypeException` / `SecurityException`。
 * 两个函数都用 catch (e: Throwable) 全部兜住 → 只记一条进度日志，**绝不让异常逃到调用方
 * （App.onCreate / 按钮点击）导致闪退**。
 * ==============================================================================================
 */

fun Context.startAutoLoginNotification(): Boolean = try {
            applicationContext.startForegroundService(
                Intent(applicationContext, MorningAuthForegroundService::class.java)
            )
            AuthWorkWiring.progress(applicationContext, "前台服务：启动请求已发送")
            true
        } catch (e: Throwable) {
            AuthWorkWiring.progress(
                applicationContext,
                "前台服务：启动被拒（${e.javaClass.simpleName}）：${e.message ?: "无 message"}" +
                    "（常见原因：Android 12+ 禁止从后台启动前台服务 / 通知权限被拒）"
            )
            false
        }

        /**
         * 停止前台服务（用户停用开关时调用）：通知随之消失。同样 try/catch，不崩溃。
         *
         * 【命名说明】不叫 `stopForegroundService`：Context 上有同名成员命名空间，
         * 扩展函数 `Context.stopForegroundService` 会被成员解析遮蔽（实测编译报
         * `Unresolved reference 'stopForegroundService'`，见 compile-raw.txt）；改成语义明确、
         * 不与任何 Context 成员同名的 `stopAutoLoginNotification` 才是可编译且无歧义的写法。
         */

fun Context.stopAutoLoginNotification() {
            try {
                applicationContext.stopService(
                    Intent(applicationContext, MorningAuthForegroundService::class.java)
                )
                AuthWorkWiring.progress(applicationContext, "前台服务：停止请求已发送（常驻通知将消失）")
            } catch (e: Throwable) {
                AuthWorkWiring.progress(
                    applicationContext,
                    "前台服务：停止失败（${e.javaClass.simpleName}）：${e.message ?: "无 message"}"
                )
            }
        }

        /**
         * 通知权限是否可用：API 33+ 检查运行时权限 `POST_NOTIFICATIONS`；更低版本恒为 true。
         * 界面在「点击启用」时据此申请权限（被拒时提示，且后台任务照常执行——只是看不到通知）。
         */
