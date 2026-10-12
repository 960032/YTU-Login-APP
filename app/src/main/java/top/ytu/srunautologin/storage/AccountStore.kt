package top.ytu.srunautologin.storage

import top.ytu.srunautologin.flow.EnabledAccountLookup
import top.ytu.srunautologin.flow.WifiAccountLookup
import java.util.logging.Logger

/**
 * ============================ v2 账号列表模型（accountsel1 任务）============================
 * 一条「已保存账号」= **一个 WiFi 对应一条记录**（保存语义 B：同一个 WiFi 只保留一条）。
 *
 * 字段（与用户口径逐字对应）：
 *  - [label]    备注名（弹窗「偏左显示账户」的显示名；通知里只允许出现它）
 *  - [username] 登录账号
 *  - [password] 登录密码（**只存在于密文内部**，绝不落明文、绝不进日志/状态文本/通知）
 *  - [ssid]     绑定的 WiFi 名（弹窗「偏右显示网络」）
 *  - [enabled]  是否参与每天早上 6:00 的网络匹配（弹窗最左侧勾选框）
 *
 * 本文件是**纯 JVM 代码**（只用 JDK），可在无 Android SDK 的环境里编译与运行
 * （见 artifacts/accountsel1/jvm-migration-test.txt）。
 */
data class SavedAccount(
    val label: String,
    val username: String,
    val password: String,
    val ssid: String = "",
    val enabled: Boolean = true
) {
    init {
        require(label.isNotBlank()) { "label 不能为空" }
    }

    /** 日志安全表示：**永不包含 password**（与 [Credential.toString] 同一口径）。 */
    override fun toString(): String =
        "SavedAccount(label=$label, username=$username, password=***, ssid=$ssid, enabled=$enabled)"
}

/**
 * v2 账号列表仓库：加密保存「每条=一个账号+绑定的 WiFi+是否勾选」，并负责 **v1 → v2 的一次性迁移**。
 *
 * 落盘：
 *  - 数据：`accounts_v2` —— 整个列表被 [SecureStore]（AES/GCM，随机 IV）加密后 Base64 存放；
 *    记录格式（仅存在于**密文内部**的明文段）：`label \t username \t password \t ssid \t enabled`，
 *    记录之间用 '\n' 分隔，字段用 [TextEscaping] 转义（label/WiFi 名里出现制表符/反斜杠也不会串行）。
 *    密码因此**不落明文**，与既有 `credentials_v1` 的加密方式完全一致。
 *  - 标记：`accounts_v2_migrated` —— 迁移已执行过的标记（幂等性的关键，见 [migrateIfNeeded]）。
 *
 * 【迁移口径（向后兼容，不可丢数据）】
 *  首次读取时，若 `accounts_v2` 不存在且 `accounts_v2_migrated` 未置位，但 `credentials_v1` 存在：
 *  把 v1 单账号（label/username/password）+ `wifi_account_map_v1` 的绑定迁移成 v2 记录，
 *  `enabled` 默认 **true**。迁移后**保留** `credentials_v1`（回滚余地，不删），但读路径改走 v2；
 *  同时把 v2 的变化镜像回 v1，使「回退安装旧版本」仍能看到账号。
 *
 * 【幂等性论证】迁移的写侧只做两件事：(a) `putString(KEY_ACCOUNTS, 加密后的列表)`；
 *  (b) `putString(KEY_MIGRATED, "1")`。第二次读取时判据 `kv.getString(KEY_ACCOUNTS)` **已非空**
 *  → 直接返回解析结果，**不会**再走迁移；即使 v2 列表被用户删空，`KEY_MIGRATED` 仍为 "1"
 *  → 也不回迁。因此重复读取（含进程重启、新实例读同一份磁盘数据）**不会产生重复记录**。
 *  唯一例外是「迁移途中进程被杀」：那一刻 `accounts_v2` 尚未写上，下次读取会再迁移一次，
 *  但源仍是**未被修改**的 v1，结果还是同一批数据，仍不产生重复。
 *
 * 【异常口径】读取侧（解密失败/密钥失效/落盘损坏）一律**降级为「空列表」+ 留痕（java.util.logging）**，
 *  绝不抛出——读方法在 UI 渲染与后台判定的同步栈上被调用，抛出去就是闪退；
 *  写入侧（[save] / [update]）保持与 [CredentialRepository.upsert] 一致的契约：加密失败抛
 *  [SecureStoreException]，由调用方（UI）捕获并显示**可见**错误。
 *
 * 本类同时实现认证链路需要的两个只读端口（[WifiAccountLookup] / [EnabledAccountLookup]）：
 *  - [labelFor] 只对**已勾选**的记录返回 label（未勾选 ⇒ 该 WiFi 视为「未绑定」⇒ 不认证）；
 *  - [hasEnabledAccountFor] 给 AuthFlow 用，拦住「未勾选但被 v1 的 selected_label_v1 兜底选中」
 *    这条路径（详见 artifacts/accountsel1/fix-report.md C 段）。
 */
class AccountStore(
    private val secureStore: SecureStore,
    private val kv: KeyValueStore,
    /** 旧键（v1）与迁移用的映射实例；默认构造一个读写同一份 [kv] 的实例。 */
    private val legacyMap: WifiAccountMap = WifiAccountMap(kv)
) : WifiAccountLookup, EnabledAccountLookup {

    companion object {
        private val LOG = Logger.getLogger("SrunAutoLogin")

        /** v2 账号列表（密文）的存储键。 */
        const val KEY_ACCOUNTS = "accounts_v2"

        /** 迁移幂等标记键（值为 "1" 表示「v1 → v2 的迁移已经做过」）。 */
        const val KEY_MIGRATED = "accounts_v2_migrated"

        /** 字段分隔符 / 记录分隔符（与 v1 同口径，避免两套编解码约定）。 */
        const val FIELD_SEPARATOR = "\t"
        const val RECORD_SEPARATOR = "\n"

        /** 一条记录的字段数。 */
        const val FIELD_COUNT = 5
    }

    // ---------------------------------- 读取 ----------------------------------

    /**
     * 全部账号（按 SSID 升序、SSID 相同按 label 升序）。**读之前先尝试一次性迁移**。
     * 无数据 / 密文不可解时返回空列表，**不抛异常**（降级 + 留痕）。
     */
    fun list(): List<SavedAccount> {
        migrateIfNeeded()
        return readV2()
    }

    /** 已勾选的账号（**早上 6:00 的网络匹配只看这一份**）。 */
    fun enabled(): List<SavedAccount> = list().filter { it.enabled }

    /** 按 SSID 找一条（SSID 为空返回 null；SSID 大小写敏感，与 [WifiAccountMap] 同口径）。 */
    fun find(ssid: String?): SavedAccount? {
        if (ssid.isNullOrEmpty()) return null
        return list().firstOrNull { it.ssid == ssid }
    }

    /** 按备注名找一条。 */
    fun findByName(label: String): SavedAccount? = list().firstOrNull { it.label == label }

    /** 当前 WiFi 生效的账号（**必须已勾选**；未勾选 = 不存在，调用方据此不认证）。 */
    fun enabledFor(ssid: String?): SavedAccount? {
        if (ssid.isNullOrEmpty()) return null
        return list().firstOrNull { it.ssid == ssid && it.enabled }
    }

    /**
     * [EnabledAccountLookup] 实现：该 SSID 是否存在**已勾选**的账号。
     * 未勾选 / 无绑定 / SSID 为空一律 false。
     */
    override fun hasEnabledAccountFor(ssid: String?): Boolean = enabledFor(ssid) != null

    /** [WifiAccountLookup] 实现：该 SSID 绑定的 label，**只对已勾选的记录返回**（未勾选返回 null）。 */
    override fun labelFor(ssid: String?): String? = enabledFor(ssid)?.label

    /** 按 label 取凭据（含未勾选的记录；是否参与认证由 [EnabledAccountLookup] 判定）。 */
    fun credentialFor(label: String): Credential? = findByName(label)?.let { toCredential(it) }

    /** 把 v2 的「当前选中」当兜底凭据（与 v1 的 selected_label_v1 同一份键）。 */
    fun selectedCredential(): Credential? =
        selectedLabel()?.let { findByName(it) }?.let { toCredential(it) }

    /** 当前选中的备注名（沿用既有 `selected_label_v1`，与 v1 存储保持一致）。 */
    fun selectedLabel(): String? = kv.getString(CredentialRepository.KEY_SELECTED)

    /** 供 UI 显示的摘要行（只含备注名与 WiFi，**不含账号/密码**）。 */
    fun summary(account: SavedAccount): String =
        "${account.label} ↔ ${account.ssid.ifBlank { "未绑定网络" }}"

    private fun toCredential(a: SavedAccount): Credential =
        Credential(
            label = a.label,
            username = a.username,
            password = a.password,
            carrier = Carrier.YTU,      // v2 未保存登录方式：既有口径下 carrier 只影响显示，不参与认证
            acId = Carrier.AC_ID        // 已冻结：字符串 "5"
        )

    // ---------------------------------- 写入 ----------------------------------

    /**
     * 保存一条账号（用户已确认的 **保存语义 B**）：
     *  - 以 **SSID 为键**：同 SSID 已存在 → **更新**该条；不存在 → **新增**（`enabled` 默认 true）；
     *  - 更新时保留该条既有的 `enabled`（勾选状态不因为再次保存而被重置）；
     *  - 成功后把该条镜像回 v1（`credentials_v1` + `wifi_account_map_v1`），供回退旧版本使用。
     *
     * 返回 true = 新增，false = 更新。
     * 加密失败时抛 [SecureStoreException]（与 [CredentialRepository] 同契约，由 UI 兜住并显示可见错误）。
     */
    fun save(
        ssid: String,
        label: String,
        username: String,
        password: String,
        enabled: Boolean? = null
    ): Boolean {
        val all = list().toMutableList()
        val idx = all.indexOfFirst { it.ssid == ssid && ssid.isNotEmpty() }
        val isNew = idx < 0
        val next = if (isNew) {
            SavedAccount(
                label = label,
                username = username,
                password = password,
                ssid = ssid,
                enabled = enabled ?: true          // 新增默认勾选（参与早上匹配）
            )
        } else {
            val old = all[idx]
            old.copy(
                label = label,
                username = username,
                password = password,
                enabled = enabled ?: old.enabled
            )
        }
        if (isNew) all.add(next) else all[idx] = next
        writeV2(all)
        mirrorToV1(next)
        return isNew
    }

    /**
     * 按传入值**增量更新**（未传的字段 = null 时保持原值，避免把未填字段覆盖成空）。
     * 找不到该 SSID 时按「新增」处理（此时 null 字段回落为空串，`enabled` 默认 true）。
     *
     * @param newSsid 需要改绑到另一个 WiFi 时传入（旧记录整体换 ssid，条数不变）。
     */
    fun update(
        ssid: String,
        label: String? = null,
        username: String? = null,
        password: String? = null,
        enabled: Boolean? = null,
        newSsid: String? = null
    ): Boolean {
        val all = list().toMutableList()
        val idx = all.indexOfFirst { it.ssid == ssid && ssid.isNotEmpty() }
        if (idx < 0) {
            save(
                ssid = newSsid ?: ssid,
                label = label ?: "",
                username = username ?: "",
                password = password ?: "",
                enabled = enabled
            )
            return true
        }
        val old = all[idx]
        all[idx] = old.copy(
            label = label ?: old.label,
            username = username ?: old.username,
            password = password ?: old.password,
            ssid = newSsid ?: old.ssid,
            enabled = enabled ?: old.enabled
        )
        writeV2(all)
        return false
    }

    /**
     * 按 SSID 删除该条，并**同步清理 v1 映射表 `wifi_account_map_v1` 中对应绑定**
     * （迁移期两者并存，只删一边会留下「指向已删账号的绑定」这种矛盾状态）。
     *
     * 若被删的是「当前选中」那条，且**再无同备注名的记录**，则清掉 `selected_label_v1`，
     * 避免它指向一条已删除的记录（用户要求：删除后处理选中状态的一致性）。
     *
     * @return true 表示确实删掉了一条。
     */
    fun delete(ssid: String): Boolean {
        val all = list().toMutableList()
        val victims = all.filter { it.ssid == ssid && ssid.isNotEmpty() }
        if (victims.isEmpty()) return false
        victims.forEach { all.remove(it) }
        writeV2(all)
        unbindLegacy(ssid)
        clearSelectionIfDangling(victims.map { it.label }.toSet())
        return true
    }

    /** 按备注名删除（同备注名的记录全部删除，含各自绑定）。 */
    fun deleteByLabel(label: String): Boolean {
        val all = list().toMutableList()
        val victims = all.filter { it.label == label }
        if (victims.isEmpty()) return false
        victims.forEach { all.remove(it) }
        writeV2(all)
        victims.map { it.ssid }.filter { it.isNotEmpty() }.forEach { unbindLegacy(it) }
        clearSelectionIfDangling(setOf(label))
        return true
    }

    /**
     * 勾选框切换：把某条记录设为「勾选/取消勾选」并**立即持久化**。
     * @return false 表示该条不存在（调用方应刷新界面）。
     */
    fun setEnabled(ssid: String, enabled: Boolean): Boolean {
        if (find(ssid) == null) return false
        update(ssid = ssid, enabled = enabled)
        return true
    }

    private fun unbindLegacy(ssid: String) {
        runCatching { legacyMap.unbind(ssid) }.onFailure {
            LOG.warning("删除账号时清理 WiFi 绑定失败（已忽略）：${it.javaClass.simpleName}: ${it.message}")
        }
    }

    private fun clearSelectionIfDangling(deletedLabels: Set<String>) {
        val remaining = readV2()
        val dangling = deletedLabels.filter { lbl -> remaining.none { it.label == lbl } }
        if (dangling.isEmpty()) return
        val selected = selectedLabel() ?: return
        if (selected in dangling) kv.remove(CredentialRepository.KEY_SELECTED)
    }

    /** 清空 v2 账号列表（**保留** `credentials_v1` 与迁移标记；仅供测试/审计）。 */
    fun clear() {
        kv.remove(KEY_ACCOUNTS)
    }

    // ------------------------------- v1 → v2 迁移 -------------------------------

    /**
     * 首次读取时的迁移（**幂等**）。迁移条件（三者同时成立）：
     *  ① `accounts_v2` 当前为空；② `accounts_v2_migrated` 未置位；③ `credentials_v1` 存在。
     * 不满足任一条即直接返回（不写盘、不改任何键）。
     *
     * 数据来源：v1 凭据 blob 解出的每条记录 + `wifi_account_map_v1` 的 `ssid → label` 映射
     * （某 label 有多个绑定 SSID 时取**字典序最小**的一个，保证可复现；取不到时 ssid 记空串，
     * 该记录仍被迁移，**不丢**这条凭据）。`enabled` 一律默认 **true**。
     */
    private fun migrateIfNeeded() {
        if (!kv.getString(KEY_ACCOUNTS).isNullOrEmpty()) return     // ① v2 已有数据
        if (kv.getString(KEY_MIGRATED) == "1") return               // ② 迁移已做过（含「之后被删空」）
        val legacyBlob = kv.getString(CredentialRepository.KEY_BLOB) ?: return  // ③ 没有 v1 数据，无需迁移

        val migrated = migrateFromLegacyV1(legacyBlob)
        if (migrated.isEmpty()) return    // v1 解不开时不置位，等密钥恢复后还有机会迁移
        writeV2(migrated)
        kv.putString(KEY_MIGRATED, "1")
        LOG.info("已把 v1 账号存储迁移到 accounts_v2：共 ${migrated.size} 条")
    }

    /** 解 v1 密文并映射成 v2 记录；解密失败降级为「空列表 + 留痕」，绝不抛。 */
    private fun migrateFromLegacyV1(legacyBlob: String): List<SavedAccount> {
        val plain = try {
            secureStore.decryptFromBase64String(legacyBlob)
        } catch (e: SecureStoreException) {
            LOG.warning("v1 凭据读取失败，迁移暂缓（不丢 v1 数据）：${e.javaClass.simpleName}: ${e.message}")
            return emptyList()
        }
        if (plain.isEmpty()) return emptyList()
        val mapping = runCatching { legacyMap.mapping() }.getOrElse { emptyMap() }
        return plain.split(CredentialRepository.RECORD_SEPARATOR)
            .filter { it.isNotEmpty() }
            .mapIndexedNotNull { index, line ->
                val f = TextEscaping.splitFields(line)
                if (f.size < 5) return@mapIndexedNotNull null
                val label = f[0].takeIf { it.isNotBlank() }
                    ?: f[1].takeIf { it.isNotBlank() }
                    ?: "账号${index + 1}"
                SavedAccount(
                    label = label,
                    username = f[1],
                    password = f[2],
                    ssid = legacySsidFor(label, mapping),
                    enabled = true
                )
            }
    }

    /** v1 时期某个 label 绑定的 SSID（多个绑定时取字典序最小的，保证结果可复现）。 */
    private fun legacySsidFor(label: String, mapping: Map<String, String>): String =
        mapping.entries.filter { it.value == label }.map { it.key }.minOrNull() ?: ""

    // ------------------------------- 编解码 -------------------------------

    private fun readV2(): List<SavedAccount> {
        val blob = kv.getString(KEY_ACCOUNTS) ?: return emptyList()
        if (blob.isEmpty()) return emptyList()
        val plain = try {
            secureStore.decryptFromBase64String(blob)
        } catch (e: SecureStoreException) {
            // 与 CredentialRepository.list() 同口径：读侧降级为「空列表」+ 留痕，**不抛**（抛出去就是闪退）
            LOG.warning("账号列表读取失败，降级为「无账号」：${e.javaClass.simpleName}: ${e.message}")
            return emptyList()
        }
        if (plain.isEmpty()) return emptyList()
        val parsed = plain.split(RECORD_SEPARATOR)
            .filter { it.isNotEmpty() }
            .mapNotNull { line ->
                val f = TextEscaping.splitFields(line)
                if (f.size < FIELD_COUNT) return@mapNotNull null
                val label = f[0]
                if (label.isBlank()) return@mapNotNull null
                SavedAccount(
                    label = label,
                    username = f[1],
                    password = f[2],
                    ssid = f[3],
                    enabled = f[4] != "0"     // 容错：只有明确的 "0" 才算未勾选
                )
            }
        return parsed.sortedWith(compareBy({ it.ssid }, { it.label }))
    }

    /** 加密写回整份列表（空列表 = 移除该键，避免留一条「有键但无记录」的歧义状态）。 */
    private fun writeV2(all: List<SavedAccount>) {
        if (all.isEmpty()) {
            kv.remove(KEY_ACCOUNTS)
            return
        }
        val plain = all.joinToString(RECORD_SEPARATOR) { a ->
            TextEscaping.joinFields(
                listOf(a.label, a.username, a.password, a.ssid, if (a.enabled) "1" else "0")
            )
        }
        kv.putString(KEY_ACCOUNTS, secureStore.encryptToBase64String(plain))
    }

    /**
     * 写回 v1（`credentials_v1` + `wifi_account_map_v1`），作为**回滚余地**：
     * v1 是升级前版本的读路径，保持同步后，用户回退安装旧版本仍能看到账号。
     * 失败只留痕、不影响 v2 已成功的写入（v2 才是当前读路径）。
     */
    private fun mirrorToV1(account: SavedAccount) {
        try {
            val repo = CredentialRepository(secureStore, kv)
            repo.upsert(
                Credential(
                    label = account.label,
                    username = account.username,
                    password = account.password,
                    carrier = Carrier.YTU,
                    acId = Carrier.AC_ID
                )
            )
            repo.select(account.label)
            if (account.ssid.isNotEmpty()) legacyMap.bind(account.ssid, account.label)
        } catch (e: Throwable) {
            LOG.warning("v1 镜像写入失败（已忽略，v2 已保存）：${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** 测试/审计用：v2 的原始落盘 Base64（内容为密文，**不含明文密码**）。 */
    fun persistedBlob(): String? = kv.getString(KEY_ACCOUNTS)

    /** 测试/审计用：迁移标记是否已置位。 */
    fun migrationDone(): Boolean = kv.getString(KEY_MIGRATED) == "1"
}