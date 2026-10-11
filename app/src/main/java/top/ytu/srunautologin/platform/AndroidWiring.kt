package top.ytu.srunautologin.platform

import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import top.ytu.srunautologin.net.DefaultWifiPermissionFlow
import top.ytu.srunautologin.net.WifiCapability
import top.ytu.srunautologin.net.WifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiScanEntry
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.net.WifiSource
import top.ytu.srunautologin.storage.CredentialRepository
import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.SecureStore
import top.ytu.srunautologin.storage.SecretKeyProvider
import top.ytu.srunautologin.storage.WifiAccountMap
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * ============================ 本文件是 Android 边界层 ============================
 * 本文件**引用 Android SDK**，因此**无法**在本机（无 Android SDK）离线编译与运行，
 * 属于「未验证」部分（见 artifacts/android-storage/storage-report.md）。
 * 其中所有可验证的逻辑都已抽到纯 JVM 的 storage/ 与 net/ 包，并已离线跑通测试。
 * ==============================================================================
 */

/**
 * KEK 的来源：Android Keystore（密钥不出安全硬件/应用沙箱，不落盘为明文）。
 * AES-256-GCM；别名固定，首次使用时生成，之后复用。
 */
class AndroidKeystoreSecretKeyProvider(
    private val alias: String = DEFAULT_ALIAS
) : SecretKeyProvider {

    companion object {
        const val DEFAULT_ALIAS = "srun_autologin_kek_v1"
        private const val PROVIDER = "AndroidKeyStore"
    }

    override fun getOrCreate(): SecretKey {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }
}

/** [KeyValueStore] 的真机实现：SharedPreferences（私有模式，仅本应用可读）。 */
class SharedPreferencesKeyValueStore(
    context: Context,
    private val prefsName: String = "srun_autologin_store"
) : KeyValueStore {

    /**
     * 加固（crashfix1 任务 C）：`getSharedPreferences` 在读取/解析已存在的 prefs XML 时理论上可能抛
     * 未受检异常（损坏文件 → XmlPullParserException/IOException 一类的运行时包装），而本类的构造点
     * 正好在 Activity.onCreate 的同步栈上。这里把「取 prefs 句柄」这一步兜住并降级为「空存储」，
     * 避免一条损坏的 prefs 文件把整个界面拖成闪退；正常路径（返回非 null 句柄）行为完全不变。
     */
    private val prefs: android.content.SharedPreferences? = try {
        context.applicationContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    } catch (e: RuntimeException) {
        Log.e(TAG, "打开 SharedPreferences 失败，降级为空存储", e)
        null
    }

    override fun getString(key: String): String? = try {
        prefs?.getString(key, null)
    } catch (e: RuntimeException) {
        Log.e(TAG, "读 SharedPreferences 失败，按空值处理", e)
        null
    }

    override fun putString(key: String, value: String) {
        try {
            prefs?.edit()?.putString(key, value)?.apply()
        } catch (e: RuntimeException) {
            Log.e(TAG, "写 SharedPreferences 失败（已忽略）", e)
        }
    }

    override fun remove(key: String) {
        try {
            prefs?.edit()?.remove(key)?.apply()
        } catch (e: RuntimeException) {
            Log.e(TAG, "删 SharedPreferences 失败（已忽略）", e)
        }
    }

    override fun keys(): Set<String> = try {
        prefs?.all?.keys?.toSet().orEmpty()
    } catch (e: RuntimeException) {
        Log.e(TAG, "枚举 SharedPreferences 键失败，按空集处理", e)
        emptySet()
    }

    private companion object {
        const val TAG = "SrunAutoLogin"
    }
}

/** [WifiSource] 的真机实现：WifiManager。无权限时返回 null / 空列表，不抛异常。 */
class AndroidWifiSource(context: Context) : WifiSource {

    /**
     * 加固（crashfix1 任务 C）：`getSystemService` 内部走 ServiceFetcher，正常返回 null 而不抛异常
     * （`as? WifiManager` 已能把 null 或类型不符都收成 null）；这里再加一层兜底，保证「取服务」这一步
     * 在 Activity.onCreate 同步栈上永不影响窗口绘制。
     */
    private val wifiManager: WifiManager? = try {
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    } catch (e: RuntimeException) {
        Log.e(TAG, "获取 WifiManager 失败，WiFi 相关能力降级为不可用", e)
        null
    }

    override fun isWifiEnabled(): Boolean = try {
        wifiManager?.isWifiEnabled ?: false
    } catch (e: SecurityException) {
        false
    }

    @Suppress("DEPRECATION")
    override fun currentSsidRaw(): String? = try {
        // API 31+ 标记 connectionInfo 为 deprecated，但仍是读取「当前连接 SSID」的唯一途径；
        // API 33+ 需要 NEARBY_WIFI_DEVICES 或 ACCESS_FINE_LOCATION。
        wifiManager?.connectionInfo?.ssid
    } catch (e: SecurityException) {
        null
    }

    override fun scanSsidEntries(): List<WifiScanEntry> = try {
        wifiManager?.scanResults.orEmpty().map { WifiScanEntry(it.SSID ?: "", it.level) }
    } catch (e: SecurityException) {
        emptyList()
    }
}

/** [WifiPermissionFlow] 的真机实现：把系统授权状态喂给纯逻辑实现。 */
class AndroidWifiPermissionFlow(context: Context) : WifiPermissionFlow {

    private val appContext = context.applicationContext
    private val delegate = DefaultWifiPermissionFlow(Build.VERSION.SDK_INT, grantedPermissions())

    override val explainText: String get() = delegate.explainText

    override fun requiredPermissions(): List<String> = delegate.requiredPermissions()

    override fun state(): WifiPermissionState {
        delegate.syncGrantedPermissions(grantedPermissions())
        return delegate.state()
    }

    override fun isRationaleShown(): Boolean = delegate.isRationaleShown()

    /** 第 1 步：UI 必须先向用户说明用途。 */
    override fun markRationaleShown() = delegate.markRationaleShown()

    /** 第 2 步：系统弹窗结果。 */
    override fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState =
        delegate.onRequestResult(outcome)

    /**
     * 加固（crashfix1 任务 C）：`checkSelfPermission` 属于「查询」而非「使用」，正常不会抛
     * SecurityException，但本方法在 Activity.onCreate 的同步栈上被反复调用（每个候选权限一次），
     * 单点异常会终止整个界面。这里逐项兜住并降级为「未授予」（等价于走降级路径，不静默放行）。
     */
    private fun grantedPermissions(): Set<String> = PERMISSION_CANDIDATES
        .filter {
            try {
                appContext.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
            } catch (e: RuntimeException) {
                Log.e(TAG, "查询权限状态失败，按未授予处理：$it", e)
                false
            }
        }
        .toSet()

    private companion object {
        val PERMISSION_CANDIDATES = listOf(
            WifiPermissionPolicy.ACCESS_FINE_LOCATION,
            WifiPermissionPolicy.ACCESS_COARSE_LOCATION,
            WifiPermissionPolicy.NEARBY_WIFI_DEVICES
        )

        const val TAG = "SrunAutoLogin"
    }
}

/**
 * UI/后台任务调用入口：WiFi 快照（只读）。
 *
 * 权限流程由 UI 通过 [AndroidWifiPermissionFlow] 走「先说明 → 再申请」；
 * 本对象只按**当前**权限状态给出快照，拒绝权限时自动降级为「只查当前 WiFi」。
 */
object WifiSnapshot {

    fun currentSsid(context: Context): String? = core(context).currentSsid()

    fun scanSsidList(context: Context): List<String> = core(context).scanSsidList()

    fun capability(context: Context): WifiCapability = core(context).capability()

    private fun core(context: Context): WifiSnapshotCore =
        WifiSnapshotCore(AndroidWifiSource(context), AndroidWifiPermissionFlow(context))
}

/** 存储层装配入口：后续 UI / 后台调度任务从这里取仓库实例。 */
object SrunStorage {

    fun secureStore(context: Context): SecureStore =
        SecureStore(AndroidKeystoreSecretKeyProvider())

    fun keyValueStore(context: Context): KeyValueStore = SharedPreferencesKeyValueStore(context)

    fun credentialRepository(context: Context): CredentialRepository =
        CredentialRepository(secureStore(context), keyValueStore(context))

    fun wifiAccountMap(context: Context): WifiAccountMap = WifiAccountMap(keyValueStore(context))
}

/** 权限名字符串与 Android 平台常量的交叉校验（供 instrumentation 测试调用）。 */
object AndroidPlatformSelfTest {
    fun checkPermissionConstants(): List<String> {
        val mismatches = ArrayList<String>()
        fun cmp(name: String, javaValue: String, policyValue: String) {
            if (javaValue != policyValue) mismatches.add("$name: android=$javaValue policy=$policyValue")
        }
        cmp("ACCESS_FINE_LOCATION", android.Manifest.permission.ACCESS_FINE_LOCATION, WifiPermissionPolicy.ACCESS_FINE_LOCATION)
        cmp("ACCESS_COARSE_LOCATION", android.Manifest.permission.ACCESS_COARSE_LOCATION, WifiPermissionPolicy.ACCESS_COARSE_LOCATION)
        cmp("NEARBY_WIFI_DEVICES", android.Manifest.permission.NEARBY_WIFI_DEVICES, WifiPermissionPolicy.NEARBY_WIFI_DEVICES)
        cmp("ACCESS_WIFI_STATE", android.Manifest.permission.ACCESS_WIFI_STATE, WifiPermissionPolicy.ACCESS_WIFI_STATE)
        cmp("CHANGE_WIFI_STATE", android.Manifest.permission.CHANGE_WIFI_STATE, WifiPermissionPolicy.CHANGE_WIFI_STATE)
        return mismatches
    }
}