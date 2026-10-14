package top.ytu.srunautologin.auth

/**
 * ============================ 纯逻辑层（无 Android 依赖，可离线核对） ============================
 *
 * 【onlinefix1 任务 A 段】「目标已达成」的统一判定。
 *
 * **为什么要它**：`E_SKIP_ALREADY_ONLINE`（服务端 `E2620 You are already online.`）的语义是
 * **目标已达成**（当前网络已在线，无需重复登录），但它在数据结构上的 `AuthResult.ok == false`
 * （因为它从 [top.ytu.srunautologin.flow.AuthSkip] 这条「跳过」通道产出，跳过的默认 `ok=false`）。
 * 于是 UI 侧 `statusOk = result.ok` 把「已在线」当成失败显示（真机日志：
 * `「立即登录」结果=未登录（code=E_SKIP_ALREADY_ONLINE，失败分类=配置缺失）`）。
 *
 * **本对象是唯一判据**：UI（`ui/MainActivity.kt`、`ui/ConfigViewModel.kt`）与任何后续调用点
 * 一律用 [isAlreadyOnline] 而不是 `result.ok` 单独判断「成功」，避免三处各写一份 `when`。
 *
 * **不改动既有数据**：本对象只做**判定**，不修改 `AuthSkipReason` / `ProbeOutcome` /
 * `AuthResult.ok` 的既有语义（那些是既有契约，离线核对可能引用）。
 * ==============================================================================================
 */
object AuthResultStatus {

    /**
     * 唯一的「已在线」结论码。
     *
     * 与 `flow.AuthSkipReason.ALREADY_ONLINE.code` 同值（那份枚举在 flow 包，此处不反向依赖）；
     * 两处**必须是同一个字符串**，改动前先 grep 全仓 `E_SKIP_ALREADY_ONLINE`。
     */
    const val CODE_ALREADY_ONLINE: String = "E_SKIP_ALREADY_ONLINE"

    /**
     * 这次认证结果是否表示「**目标已达成**」（当前网络已在线，不存在需要用户处理的问题）。
     *
     * 只认 [CODE_ALREADY_ONLINE]：其它 `E_SKIP_*`（`E_SKIP_NO_SSID` / `E_SKIP_UNBOUND` /
     * `E_SKIP_SSID_MISMATCH` / `E_SKIP_NOT_SRUN` / `E_SKIP_PROBE_UNCERTAIN`）语义仍是
     * 「本次跳过、需等条件变化」，**一律返回 false**。
     */
    fun isAlreadyOnline(result: AuthResult?): Boolean =
        result != null && result.code == CODE_ALREADY_ONLINE

    /** 便捷重载：只用结论码判断（日志/编排层常常只拿到 code 字符串）。 */
    fun isAlreadyOnlineCode(code: String?): Boolean = code == CODE_ALREADY_ONLINE
}
