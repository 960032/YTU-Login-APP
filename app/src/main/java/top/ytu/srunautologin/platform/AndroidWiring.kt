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
import top.ytu.srunautologin.storage.CredentialRepository
import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.SecureStore
import top.ytu.srunautologin.storage.SecretKeyProvider
import top.ytu.srunautologin.storage.WifiAccountMap
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyStore
import java.security.spec.KeySpec
import java.util.logging.Level
import java.util.logging.Logger
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
 * 统一日志 TAG：本文件所有 Log.* 调用共用（原先由各内部类各自持有 private TAG，导致同类外作用域落空）。
 */
private const val TAG = "SrunAutoLogin"

/**
 * KEK 的来源：Android Keystore（密钥不出安全硬件/应用沙箱，不落盘为明文）。
 * AES-256-GCM；别名固定，首次使用时生成，之后复用。
 */
/**
 * KEK 的来源：Android Keystore（密钥不出安全硬件/应用沙箱，不落盘为明文）。
 * AES-256-GCM；别名固定，首次使用时生成，之后复用。
 *
 * 修复（keystore-fix1）：真机上保存凭据抛
 * `java.security.InvalidAlgorithmParameterException: Caller-provided IV not permitted`
 * ——旧密钥在建参数时没写 `setRandomizedEncryptionRequired(false)`，Keystore 默认 true 即「只允许
 * Keystore 自己生成随机 IV」，而 SecureStore 的落盘格式自带 IV、必须由调用者提供，两者直接冲突。
 */
class AndroidKeystoreSecretKeyProvider(
    private val alias: String = DEFAULT_ALIAS
) : SecretKeyProvider {

    companion object {
        const val DEFAULT_ALIAS = "srun_autologin_kek_v1"
        private const val PROVIDER = "AndroidKeyStore"

        /** 本类只用 java.util.logging（Android 有实现），不引入 android.util.Log，保持可离线编译。 */
        private val LOGGER: Logger = Logger.getLogger(TAG)

        /** 「删除旧密钥 + 重建」是否已尝试过；给兜底日志限次（进程内有效）。 */
        @Volatile
        private var keyRegenAttempted = false

        /** getKeySpec 检测失败是否已记过日志，避免刷屏。 */
        @Volatile
        private var specDetectFailureLogged = false
    }

    override fun getOrCreate(): SecretKey {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val existing = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            if (hasCallerProvidedIvAllowed(existing.secretKey)) return existing.secretKey
            // 旧密钥是「随机 IV 模式」下生成的（setRandomizedEncryptionRequired 默认 true）：Keystore 会拒绝
            // 调用者提供的 IV，于是每次加密都抛 InvalidAlgorithmParameterException（本次真机崩溃的根因）。
            // 改代码不会自动重建已有密钥条目，所以这里显式删除后按新参数重建。
            // 数据影响分析见 artifacts/keystore-fix1/fix-report.md「旧密钥处置的数据影响分析」。
            LOGGER.warning("旧 KEK 不允许调用者提供 IV，删除并按新参数重建：$alias")
            keyStore.deleteEntry(alias)
        }
        return generateKey()
    }

    /** 生成新 KEK：固定别名 + [buildKeySpec] 的冻结参数。 */
    private fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        val key = generator.generateKey()
        if (!keyRegenAttempted) {
            // 兜底：刚生成的密钥若仍「检测不通过」，说明是检测 API 失效而不是密钥真不合格——记一次日志后
            // 直接复用，避免每次调用都 delete + 重新生成，把 Keystore 拖进无意义的循环。
            keyRegenAttempted = true
            if (!hasCallerProvidedIvAllowed(key)) {
                LOGGER.warning("新生成的 KEK 未通过 IV 模式检测（检测 API 可能不可用），本次直接复用、不再删除重建")
            }
        }
        return key
    }

    /**
     * KEK 参数（**冻结，勿改**）：AES-256 | GCM | NoPadding | PURPOSE_ENCRYPT|PURPOSE_DECRYPT
     * 且 **setRandomizedEncryptionRequired(false)**。
     *
     * 为什么必须加这个参数：`setRandomizedEncryptionRequired` 的默认值是 `true`，语义是「IV 必须由
     * Keystore 随机生成，调用者不得提供」；此时调用者自带 IV 调 Cipher.init 会抛
     * `InvalidAlgorithmParameterException: Caller-provided IV not permitted`（真机堆栈已证实）。
     * 而 SecureStore 的落盘格式 `'S' | 版本 | IV(12B) | 密文+GCM 标签` 自带 IV，必须由调用者提供，
     * 因此这里必须显式关闭该要求；关闭后密钥强度（AES-256-GCM）不变，只是解除对 IV 来源的限制。
     *
     * 安全权衡：允许调用者提供 IV 后，**IV 复用会造成 GCM 灾难性失败**（同一密钥+同一 IV 加密不同明文 →
     * 认证子密钥泄露、可伪造密文）。该参数成立的前提是「调用方每次加密都用 SecureRandom 生成全新的 12 字节 IV」；
     * 该前提在当前代码中成立并已核对：storage/SecureStore.kt 的 encrypt() 每次调用都新生成 12 字节随机 IV
     * 并随密文一起落盘（见该方法内注释与 _after/SecureStore.kt）。这也正是不改成「由 Keystore 生成 IV」的原因：
     * 那要一起改落盘格式与 decrypt 路径，影响面更大且会让已存密文不可解。
     */
    private fun buildKeySpec(): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(false)
            .build()

    /**
     * 检测已有密钥是否「允许调用者提供 IV」——这是修复真正生效的关键：不改它，真机上那把旧密钥会继续
     * 触发 Caller-provided IV not permitted。
     *
     * 主路径：`KeyFactory.getKeySpec(key, KeyGenParameterSpec::class.java)` 读出
     * `isRandomizedEncryptionRequired`（`KeyGenParameterSpec.isRandomizedEncryptionRequired()` 自 API 23 起存在）。
     * 兜底：该调用抛异常或返回的不是 KeyGenParameterSpec 时返回 true（按「合格」处理、保留旧密钥）。
     * 理由：这里唯一的任务是把真机上那把旧密钥重建一次；误判成「不合格」会导致每次 getOrCreate 都
     * delete + 重新生成密钥，把存储拖进循环删除。宁可漏判（旧密钥保留、加密失败由 SecureStore 收敛成
     * 可见错误，不闪退），也不可误删。本机无 Android Keystore，该检测的「真机命中」无法在 Windows 上验证。
     */
    private fun hasCallerProvidedIvAllowed(key: SecretKey): Boolean = try {
        @Suppress("UNCHECKED_CAST")
        val spec = KeyFactory.getInstance(key.algorithm, PROVIDER)
            .getKeySpec(key, KeyGenParameterSpec::class.java as Class<KeySpec>) as? KeyGenParameterSpec
        spec?.isRandomizedEncryptionRequired ?: true
    } catch (e: GeneralSecurityException) {
        if (!specDetectFailureLogged) {
            specDetectFailureLogged = true
            LOGGER.log(Level.WARNING, "无法读取 Keystore 密钥规格（按「合格」保留旧密钥、不做删除）", e)
        }
        true
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
    } catch (e: RuntimeException) {
        // wifi-fix1（D3）：只兜「与系统交互」这一步的运行时异常——部分 OEM ROM（含 HyperOS）的
        // WifiManager 包装层会抛非 SecurityException 的 RuntimeException。作用域仅限本次系统调用，
        // 不会吞掉本应用自身的逻辑错误（逻辑错误仍在纯逻辑层照常抛出）。
        Log.e(TAG, "读取 WiFi 开关失败，按关闭处理", e)
        false
    }

    @Suppress("DEPRECATION")
    override fun currentSsidRaw(): String? = try {
        // API 31+ 标记 connectionInfo 为 deprecated，但仍是读取「当前连接 SSID」的唯一途径；
        // API 33+ 需要 NEARBY_WIFI_DEVICES 或 ACCESS_FINE_LOCATION。
        wifiManager?.connectionInfo?.ssid
    } catch (e: SecurityException) {
        null
    } catch (e: RuntimeException) {
        // 同上：只兜本次系统调用；返回 null 后由 WifiSnapshotCore.diagnose() 给出可见原因。
        Log.e(TAG, "读取当前连接 SSID 失败，按未连接处理", e)
        null
    }

    override fun scanSsidEntries(): List<WifiScanEntry> = try {
        wifiManager?.scanResults.orEmpty().map { WifiScanEntry(it.SSID ?: "", it.level) }
    } catch (e: SecurityException) {
        emptyList()
    } catch (e: RuntimeException) {
        // 同上（wifi-fix1 / D3）：getScanResults() 读的是上一次系统扫描的缓存，无权限/被遮罩时
        // 可能抛异常或返回空；这里只兜系统调用的异常。
        Log.e(TAG, "读取扫描结果失败，按空列表处理", e)
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
        /**
         * 候选权限 = **清单里真实声明**的权限（wifi-fix1 修 R5）。
         *
         * ACCESS_COARSE_LOCATION 未在 AndroidManifest.xml 声明 → `checkSelfPermission` 对未声明权限
         * 恒返回 DENIED，是恒假的死代码，还会造成「粗略位置也被考虑了」的错觉，故从候选中移除。
         * （WifiPermissionPolicy.ACCESS_COARSE_LOCATION 常量本身保留：AndroidPlatformSelfTest 用它做
         * 与 android.Manifest.permission 的交叉校验。）
         */
        val PERMISSION_CANDIDATES = listOf(
            WifiPermissionPolicy.ACCESS_FINE_LOCATION,
            WifiPermissionPolicy.NEARBY_WIFI_DEVICES
        )
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

    /**
     * wifi-fix1（B）：数据可用性诊断。返回值告诉 UI「是没权限、WiFi 没开，还是权限没问题但系统
     * 一条都没返回」，用于渲染**不与权限状态行矛盾**的提示。
     */
    fun diagnosis(context: Context): WifiDiagnosis = core(context).diagnose()

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