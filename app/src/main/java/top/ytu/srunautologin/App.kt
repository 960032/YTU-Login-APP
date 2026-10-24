package top.ytu.srunautologin

import android.app.Application
import top.ytu.srunautologin.work.AutoLoginController

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // This may be a process started by a job. Restore idempotently rather than
        // replacing the very job that created the process.
        AutoLoginController.restore(this, "process-start")
    }
}
