package top.ytu.srunautologin.work

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Removes alarm channels left by older versions; periodic work now has one scheduler. */
object MorningAuthRuntime {
    const val ACTION_MORNING = "top.ytu.srunautologin.action.MORNING_AUTH"
    const val EXTRA_REASON = "morning_reason"

    fun cancelLegacyAlarms(context: Context) {
        val app = context.applicationContext
        val alarms = app.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        for (requestCode in listOf(23057, 23058)) {
            val intent = Intent(app, MorningAlarmReceiver::class.java).setAction(ACTION_MORNING)
            val pending = PendingIntent.getBroadcast(app, requestCode, intent,
                PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE)
            if (pending != null) { alarms.cancel(pending); pending.cancel() }
        }
    }

    fun ensurePeriodicCheck(context: Context): Boolean {
        cancelLegacyAlarms(context)
        return AuthWorkWiring.scheduler(context).ensurePeriodic()
    }
}

/** Kept only to address old PendingIntent identities when cancelling them. */
class MorningAlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) = Unit
}
