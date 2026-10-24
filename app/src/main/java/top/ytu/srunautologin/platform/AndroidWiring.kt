package top.ytu.srunautologin.platform

import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import top.ytu.srunautologin.net.DefaultWifiPermissionFlow
import top.ytu.srunautologin.net.WifiCapability
import top.ytu.srunautologin.net.WifiDiagnosis
import top.ytu.srunautologin.net.WifiPermissionFlow
import top.ytu.srunautologin.net.WifiPermissionPolicy
import top.ytu.srunautologin.net.WifiPermissionRequestOutcome
import top.ytu.srunautologin.net.WifiPermissionState
import top.ytu.srunautologin.net.WifiScanEntry
import top.ytu.srunautologin.net.WifiSnapshotCore
import top.ytu.srunautologin.net.WifiSource
import top.ytu.srunautologin.storage.AccountStore
import top.ytu.srunautologin.storage.CredentialRepository
import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.SecureStore
import top.ytu.srunautologin.storage.SecretKeyProvider
import top.ytu.srunautologin.storage.WifiAccountMap
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val TAG = "SrunAutoLogin"

/** Reuses the existing key; IV generation is delegated to the cipher provider. */
class AndroidKeystoreSecretKeyProvider(private val alias: String = DEFAULT_ALIAS) : SecretKeyProvider {
    override fun getOrCreate(): SecretKey = synchronized(KEY_LOCK) {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val existing = store.getEntry(alias, null)
        if (existing is KeyStore.SecretKeyEntry) return@synchronized existing.secretKey
        check(!store.containsAlias(alias)) { "已有凭据密钥不可用，已保留原密钥和数据" }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build())
        generator.generateKey()
    }

    companion object {
        const val DEFAULT_ALIAS = "srun_autologin_kek_v1"
        private const val PROVIDER = "AndroidKeyStore"
        private val KEY_LOCK = Any()
    }
}
class SharedPreferencesKeyValueStore(
    context: Context,
    private val prefsName: String = "srun_autologin_store"
) : KeyValueStore {
    private val prefs = context.applicationContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    override fun getString(key: String): String? = prefs.getString(key, null)
    override fun keys(): Set<String> = prefs.all.keys.toSet()
    override fun putString(key: String, value: String) {
        val editor = prefs.edit().putString(key, value)
        if (key == "srun_log_v1" || key == "srun_auth_progress_v1") editor.apply()
        else check(editor.commit()) { "设置未能写入存储" }
    }
    override fun putAll(changes: Map<String, String?>) {
        val editor = prefs.edit()
        changes.forEach { (key, value) -> if (value == null) editor.remove(key) else editor.putString(key, value) }
        check(editor.commit()) { "设置未能写入存储" }
    }
    override fun remove(key: String) {
        check(prefs.edit().remove(key).commit()) { "设置未能从存储删除" }
    }
}
class AndroidWifiSource(context: Context) : WifiSource {

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
    } catch (e: RuntimeException) {
        Log.e(TAG, "读取 WiFi 开关失败，按关闭处理", e)
        false
    }

    @Suppress("DEPRECATION")
    override fun currentSsidRaw(): String? = try {
        wifiManager?.connectionInfo?.ssid
    } catch (e: SecurityException) {
        null
    } catch (e: RuntimeException) {
        Log.e(TAG, "读取当前连接 SSID 失败，按未连接处理", e)
        null
    }

    override fun scanSsidEntries(): List<WifiScanEntry> = try {
        wifiManager?.scanResults.orEmpty().map { WifiScanEntry(it.SSID ?: "", it.level) }
    } catch (e: SecurityException) {
        emptyList()
    } catch (e: RuntimeException) {
        Log.e(TAG, "读取扫描结果失败，按空列表处理", e)
        emptyList()
    }
}

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

    override fun markRationaleShown() = delegate.markRationaleShown()

    override fun onRequestResult(outcome: WifiPermissionRequestOutcome): WifiPermissionState =
        delegate.onRequestResult(outcome)

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
            WifiPermissionPolicy.NEARBY_WIFI_DEVICES
        )
    }
}

object WifiSnapshot {

    fun currentSsid(context: Context): String? = core(context).currentSsid()

    fun scanSsidList(context: Context): List<String> = core(context).scanSsidList()

    fun capability(context: Context): WifiCapability = core(context).capability()

    fun diagnosis(context: Context): WifiDiagnosis = core(context).diagnose()

    private fun core(context: Context): WifiSnapshotCore =
        WifiSnapshotCore(AndroidWifiSource(context), AndroidWifiPermissionFlow(context))
}

object SrunStorage {

    fun secureStore(context: Context): SecureStore =
        SecureStore(AndroidKeystoreSecretKeyProvider())

    fun keyValueStore(context: Context): KeyValueStore = SharedPreferencesKeyValueStore(context)

    fun credentialRepository(context: Context): CredentialRepository =
        CredentialRepository(secureStore(context), keyValueStore(context))

    fun accountStore(context: Context): AccountStore =
        AccountStore(secureStore(context), keyValueStore(context))

    fun wifiAccountMap(context: Context): WifiAccountMap = WifiAccountMap(keyValueStore(context))
}

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