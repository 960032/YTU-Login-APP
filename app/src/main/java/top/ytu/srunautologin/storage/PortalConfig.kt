package top.ytu.srunautologin.storage

import java.net.URI
import java.net.URISyntaxException

/**
 * Portal（校园网门户）地址配置：**用户保存的值 > 代码默认值**。
 *
 * 为什么需要它：不同校区的 SRun 门户地址不同（例如烟台大学本校区实测可用地址为
 * [DEFAULT_PORTAL]），若把地址写死在代码里，其他用户装上后必然连不通。
 *
 * 复用既有的 [KeyValueStore] 抽象，**不新增任何存储机制、不引入新依赖**：
 *  - 真机：platform 包的 `SharedPreferencesKeyValueStore`（同一份 SharedPreferences，
 *    因此**改完重启 App 仍然生效**）；
 *  - 离线核对：`InMemoryKeyValueStore`（同一实例即等价于「同一次安装」），
 *    或 `FileKeyValueStore`（新建实例读同一目录即等价于「进程重启」）。
 *
 * 地址归一化的**唯一权威**是 [top.ytu.srunautologin.auth.SrunRequestBuilder.normalizePortal]
 * （去空白 / 去尾部 '/' / 无协议补 `http://`），本文件**不重复实现**它，只做两件额外的事：
 *  1. 把用户输入收敛成「纯主机」形态（剥离用户可能输入的协议、端口、路径），使保存进存储的值本身就是规范形态；
 *  2. 校验主机合法性（非法输入返回 null，由调用方给用户**可见提示**，不静默接受）。
 */
object PortalConfig {

    /** 存储键（与 SecureStore / WifiAccountMap 的键风格一致：小写下划线 + 版本号）。 */
    const val KEY_PORTAL: String = "srun_portal_v1"

    /** 代码默认 Portal 主机（与 [top.ytu.srunautologin.flow.AuthFlow.DEFAULT_PORTAL] 逐字一致）。 */
    const val DEFAULT_PORTAL: String = "202.194.116.116"

    private const val DEFAULT_SCHEME = "http://"

    /**
     * 主机名合法形状：字母/数字/连字符的标签（点分），或点分十进制 IPv4。
     * 不合格的输入（空白、含空格、含非法字符）返回 null。
     */
    private val HOST_PATTERN = Regex("^([A-Za-z0-9]([A-Za-z0-9-]{0,62})?)(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*$")

    /**
     * 用户输入 → 规范化的 Portal 基地址（**主机形态，无路径、无尾斜杠**；形如 `http://202.194.116.116`）。
     *
     * 容忍：首尾空白、带/不带 `http://`、`https://`、尾斜杠、误粘的路径、带端口。
     * 非法（空、含空格、IPv6 字面量、端口非数字）→ 返回 null。
     */
    fun normalize(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val withScheme =
            if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) trimmed
            else DEFAULT_SCHEME + trimmed
        val host = try {
            URI(withScheme).host
        } catch (e: URISyntaxException) {
            null
        } ?: return null
        if (host.isEmpty() || !HOST_PATTERN.matches(host)) return null
        return DEFAULT_SCHEME + host
    }

    /**
     * 读取生效的 Portal 基地址：**用户保存的值（经校验）优先，缺失或非法时回落到 [DEFAULT_PORTAL]**。
     * 返回值与 [top.ytu.srunautologin.auth.SrunRequestBuilder.normalizePortal] 的输出形态一致
     * （`http://主机`），调用方无需再规范化。
     */
    fun read(store: KeyValueStore?): String =
        readHost(store)?.let { DEFAULT_SCHEME + it } ?: (DEFAULT_SCHEME + DEFAULT_PORTAL)

    /** 读取生效的 Portal **主机**（不含协议）：用户保存值优先，缺失或非法时回落默认值。 */
    fun readHost(store: KeyValueStore?): String? =
        store?.getString(KEY_PORTAL)?.let { normalize(it)?.removePrefix(DEFAULT_SCHEME) }
            ?: DEFAULT_PORTAL

    /** 把用户输入写入存储；非法输入返回 null（**不写脏值、不静默覆盖旧值**）。 */
    fun write(store: KeyValueStore, raw: String): String? {
        val normalized = normalize(raw) ?: return null
        val host = normalized.removePrefix(DEFAULT_SCHEME)
        store.putString(KEY_PORTAL, host)
        return normalized
    }
}
