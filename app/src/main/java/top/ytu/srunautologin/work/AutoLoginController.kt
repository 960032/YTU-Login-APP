package top.ytu.srunautologin.work

import android.content.Context
import top.ytu.srunautologin.platform.ActiveWifiSessions
import top.ytu.srunautologin.platform.SrunStorage

/** One lifecycle entry point for app start, configuration changes and the user switch. */
object AutoLoginController {
    @Synchronized
    fun restore(context: Context, reason: String) {
        val app = context.applicationContext
        try {
            if (!AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(app))) {
                stop(app, reason)
                return
            }
            NetworkWatcher.start(app)
            MorningAuthRuntime.cancelLegacyAlarms(app)
            AuthWorkWiring.scheduler(app).ensurePeriodic()
        } catch (e: RuntimeException) {
            AuthWorkWiring.progress(app, "自动登录恢复失败（$reason，${e.javaClass.simpleName}）")
        }
    }

    fun setEnabled(context: Context, enabled: Boolean): Boolean {
        val app = context.applicationContext
        val actual = AutoLoginSwitch.setEnabled(SrunStorage.keyValueStore(app), enabled)
        if (actual) {
            restore(app, "user-enabled")
            AuthWorkWiring.resetBackoff(app, clearUserAction = true)
            requestCheck(app, "user-enabled", reset = true)
            app.startAutoLoginNotification()
        } else stop(app, "user-disabled")
        return actual
    }

    fun onUserVisible(context: Context) {
        if (AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(context.applicationContext))) {
            restore(context, "user-visible")
            context.startAutoLoginNotification()
        }
    }

    fun onConfigurationChanged(context: Context, reason: String) {
        val app = context.applicationContext
        AuthWorkWiring.resetBackoff(app, clearUserAction = true)
        ActiveWifiSessions.cancelAll()
        AuthWorkWiring.scheduler(app).cancelPendingAuth()
        NetworkWatcher.stop()
        restore(app, reason)
        requestCheck(app, reason, reset = true)
    }

    fun requestCheck(context: Context, reason: String, reset: Boolean = false, delayMillis: Long = 0L) {
        val app = context.applicationContext
        if (!AutoLoginSwitch.isEnabled(SrunStorage.keyValueStore(app))) return
        if (reset) AuthWorkWiring.resetBackoff(app)
        AuthWorkWiring.scheduler(app).enqueueAuth(delayMillis, reason)
    }

    @Synchronized
    private fun stop(context: Context, reason: String) {
        ActiveWifiSessions.cancelAutomatic()
        NetworkWatcher.stop()
        AuthWorkWiring.scheduler(context).cancelAll()
        MorningAuthRuntime.cancelLegacyAlarms(context)
        context.stopAutoLoginNotification()
        AuthWorkWiring.progress(context, "自动登录已停止（$reason）")
    }
}
