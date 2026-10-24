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
import android.location.LocationManager
import android.os.Build
import android.os.IBinder
import top.ytu.srunautologin.platform.SrunStorage
import top.ytu.srunautologin.ui.MainActivity

/** User-visible monitoring. Authentication itself remains a bounded background job. */
class MorningAuthForegroundService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            AutoLoginController.setEnabled(this, false)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(this))) {
            stopSelf()
            return START_NOT_STICKY
        }
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "校园网自动登录", NotificationManager.IMPORTANCE_LOW).apply {
            setShowBadge(false)
        })
        val content = PendingIntent.getActivity(this, NOTIFICATION_ID,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, NOTIFICATION_ID + 1,
            Intent(this, MorningAuthForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val publicVersion = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("校园网自动登录")
            .setContentText("网络监测已启用")
            .build()
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("校园网自动登录已启用")
            .setContentText("连接已配置的 WiFi 后检查认证状态")
            .setContentIntent(content)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .addAction(Notification.Action.Builder(null, "停用", stop).build())
            .build()
        try {
            val locationAvailable = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED &&
                ((getSystemService(Context.LOCATION_SERVICE) as? LocationManager)?.let {
                    if (Build.VERSION.SDK_INT >= 28) it.isLocationEnabled else true
                } == true)
            if (Build.VERSION.SDK_INT >= 34) {
                var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                if (locationAvailable) types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
                startForeground(NOTIFICATION_ID, notification, types)
            } else if (Build.VERSION.SDK_INT >= 29 && locationAvailable) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            } else startForeground(NOTIFICATION_ID, notification)
            AutoLoginController.restore(this, "monitor-service")
        } catch (e: RuntimeException) {
            AuthWorkWiring.progress(this, "自动登录监测服务启动失败（${e.javaClass.simpleName}），定期任务仍会保留")
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        AuthWorkWiring.progress(this, "系统要求停止监测服务，已保留定期认证任务")
        stopSelf()
    }

    companion object {
        const val CHANNEL_ID = "srun_auto_login_channel"
        const val NOTIFICATION_ID = 23073
        private const val ACTION_STOP = "top.ytu.srunautologin.STOP_AUTO_LOGIN"
        fun notificationPermissionGranted(context: Context): Boolean = Build.VERSION.SDK_INT < 33 ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }
}

fun Context.startAutoLoginNotification(): Boolean = try {
    applicationContext.startForegroundService(Intent(applicationContext, MorningAuthForegroundService::class.java))
    true
} catch (e: RuntimeException) {
    AuthWorkWiring.progress(applicationContext, "监测服务暂未启动（${e.javaClass.simpleName}），请打开应用恢复监测")
    false
}

fun Context.stopAutoLoginNotification() {
    applicationContext.stopService(Intent(applicationContext, MorningAuthForegroundService::class.java))
}
