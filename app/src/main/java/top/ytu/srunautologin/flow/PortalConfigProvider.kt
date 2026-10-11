package top.ytu.srunautologin.flow

import top.ytu.srunautologin.storage.KeyValueStore
import top.ytu.srunautologin.storage.PortalConfig

/**
 * 从**持久化配置**读取 Portal 地址的 [PortalProvider] 实现。
 *
 * 装配矩阵（全部走同一份配置，避免「默认值散落」）：
 *  - 前台「立即登录」：`MainActivity.buildAuthFlow()` 构造它（Activity 已 attach，Context 可用）；
 *  - 后台自动登录：`work/AndroidAuthWorkWiring.kt` 的 `AndroidAuthRunEnv` 用 applicationContext 构造它
 *    （每次运行现取，因此用户在界面改完地址后，下一次后台认证立刻用新地址，无需重启）；
 *  - 离线核对：注入 `InMemoryKeyValueStore` / `FileKeyValueStore` 即可验证读写往返。
 *
 * 语义：**用户保存的值（经校验）优先，缺失或非法时回落到 [PortalConfig.DEFAULT_PORTAL]**。
 * 本类不复制归一化逻辑——归一化的唯一权威是
 * [top.ytu.srunautologin.auth.SrunRequestBuilder.normalizePortal]（[PortalConfig] 内部调用同一权威）。
 *
 * 注意：**本类构造不触碰 Context**（只持有已经建好的 [KeyValueStore]），
 * 因此可安全地放在 Activity 的 `by lazy` 里（crashfix2 约束）。
 */
class StoredPortalProvider(private val store: KeyValueStore) : PortalProvider {
    override fun portal(): String = PortalConfig.read(store)
}
