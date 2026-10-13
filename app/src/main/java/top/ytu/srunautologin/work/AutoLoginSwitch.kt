package top.ytu.srunautologin.work

import top.ytu.srunautologin.storage.KeyValueStore

/**
 * ============================ 「后台自动登录」总开关（纯逻辑，可离线核对）============================
 * 本文件**不引用任何 Android API**，与 [RetryPolicy] / [AuthWorkCoordinator] 同属可离线编译的纯逻辑层。
 *
 * 【为什么需要它（用户原话）】
 *   用户此前关闭过「自动登录」开关，而 removemorning1 把开关 UI 与全部闸门一起删掉了 ——
 *   结果是他无法再「启用」，后台登录在默认配置下也看不到任何开关状态。用户明确要求：
 *     - 恢复控制开关（按钮 + 绿/红状态文本）；
 *     - **默认启用**（首次安装/升级后就是「自动登录已启用」）；
 *     - 停用时：不显示常驻通知、网络变化不生效、15 分钟周期保底也不生效。
 *
 * 【默认值为什么是 true，以及为什么用「新键」而不是复用旧键 `srun_morning_enabled_v1`】
 *   1. 默认值必须是 true：用户的核心需求就是「后台自动登录要工作」，旧设计默认 false
 *      正是他以为「功能坏了」的原因；
 *   2. 旧键 `srun_morning_enabled_v1`（morning1 的 `MorningStateStore.KEY_ENABLED`）在**真机上
 *      极可能已经是 false**（他当年把开关关过）。若复用它并把缺省值改成 true，升级后读到的仍是
 *      那个历史 false → **仍然是停用**，与「默认启用」的要求直接矛盾；
 *   3. 因此这里用一个**新键** `srun_auto_login_enabled_v1`：真机上它必然缺省（null）→ 按
 *      [DEFAULT_ENABLED] = true 处理 → 升级后一定是「已启用」。旧键保留为惰性数据，本文件
 *      既不读也不写它（不产生「读到旧 false」的路径）。
 *
 * 【闸门语义（所有后台入口共用一处判断）】
 *   停用 ⇒ 直接返回：**不注册监听、不排期、不认证**；
 *   启用 ⇒ 保持既有全部行为（网络变化触发 + 15 分钟周期保底 + 四段判断链）。
 *   调用方必须调用 [gateReason] 取日志文本并写一条「自动登录已停用，跳过」。
 * ==============================================================================================
 */
object AutoLoginSwitch {

    /**
     * 持久化键。**新键**（不复用 morning1 的 `srun_morning_enabled_v1`，理由见类注释）。
     * 与既有 `srun_auth_*` / `srun_probe_attempt_v1` 键共存于同一份键值存储。
     */
    const val KEY_ENABLED = "srun_auto_login_enabled_v1"

    /** 缺省值：**启用**。仅当存储里明确存在 "0" / "false" 时才视为停用。 */
    val DEFAULT_ENABLED: Boolean = true

    /** 存储里没有这个键 ⇒ 首次安装/升级 ⇒ 启用。 */
    fun isDefault(kv: KeyValueStore): Boolean = kv.getString(KEY_ENABLED) == null

    /** 读开关。任何异常/非 "0"/"false" 的值都按「启用」处理（绝不因读失败而静默停掉后台登录）。 */
    fun isEnabled(kv: KeyValueStore): Boolean {
        val raw = try {
            kv.getString(KEY_ENABLED)
        } catch (e: Throwable) {
            return DEFAULT_ENABLED
        } ?: return DEFAULT_ENABLED
        return !(raw == "0" || raw.equals("false", ignoreCase = true))
    }

    /**
     * 写开关（**立即持久化**，用户点击后立刻生效）。
     *
     * @return 写入后的真实状态（读回校验后的值；写失败时返回传入值，不抛异常）
     */
    fun setEnabled(kv: KeyValueStore, enabled: Boolean): Boolean = try {
        kv.putString(KEY_ENABLED, if (enabled) "1" else "0")
        isEnabled(kv)
    } catch (e: Throwable) {
        enabled
    }

    /** 把存储值编码/解码为界面展示用的开关状态（纯函数，可离线核对）。 */
    fun encode(enabled: Boolean): String = if (enabled) "1" else "0"

    /**
     * 后台入口的闸门：返回 null 表示「启用、可以继续」；
     * 返回非 null 表示「已停用」——该字符串就是要写进日志的那句「跳过」文案。
     *
     * @param entry 入口名称（如 "App.onCreate" / "NetworkChangeReceiver" / "AuthJobService"），
     *        只用于日志定位，不得放入任何账号/密码。
     */
    fun gateReason(kv: KeyValueStore, entry: String): String? =
        if (isEnabled(kv)) null else "自动登录已停用，跳过：$entry"
}