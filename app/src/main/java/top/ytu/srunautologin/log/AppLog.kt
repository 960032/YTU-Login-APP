package top.ytu.srunautologin.log

import top.ytu.srunautologin.storage.KeyValueStore

/**
 * 应用内「运行日志」（logfix1 任务 A 段）。
 *
 * 需求（用户原话）：在界面最下侧添加「日志」按钮，点击后打开日志窗口；
 * 日志应记录**本应用执行和用户输入的所有操作**，包括修改账户设置 / 切换登录状态 /
 * 检测网络是否符合登录要求 / 登录成功与否等。
 *
 * 设计要点（与用户已确认的决策逐条对应）：
 *  1. **隐私**：账户只记前 3 位（[maskAccount]）；**绝不记密码**（[sanitize] 把形如
 *     `password=…` / `密码：…` 的值替换成 `***`；[recordWithSecrets] 对已知密码做硬替换）。
 *  2. **容量**：环形上限 [MAX_ENTRIES] = 1000 条 + 落盘（跨重启保留）。
 *  3. **不阻塞主流程**：任何一次写入失败都被吞掉（[record] 内部 runCatching），
 *     日志系统的问题绝不允许影响认证/界面主流程。
 *  4. **线程**：内部状态访问用 [LOCK] 串行化，主线程与后台 worker 线程可同时调用。
 *
 * 存储方案（派发指令要求：若判断单键放不下或有性能问题要说明）：
 *  取「**单键 + 换行分隔**」方案。1000 条 × 约 60 字符 ≈ 60 KB；Android 端 SharedPreferences
 *  在内存里持有的就是一份 Map<String,String>，60 KB 一次写入开销可接受；且
 *  [top.ytu.srunautologin.platform.SharedPreferencesKeyValueStore.putString] 用的是 `apply()`
 *  （异步落盘、不阻塞调用线程）。分片方案会带来「取全部 / 清空 / 环形裁剪」的多键一致性问题，
 *  在 60 KB 量级上没有收益，故不采用。容量实测见 artifacts/logfix1/fix-report.md。
 */
object AppLog {

    /** 环形上限：最近 1000 条（用户确认的决策）。 */
    const val MAX_ENTRIES: Int = 1000

    /** 存储键（用户建议值，逐字采用）。 */
    const val KEY: String = "srun_log_v1"

    /** 单条日志的最大长度（防止一条超长行把整块存储撑大；超出截断并加省略号）。 */
    private const val MAX_LINE_CHARS: Int = 300

    /** 进程内串行锁：日志可能同时来自主线程（UI 操作）与 worker 线程（认证/探测）。 */
    private val LOCK = Any()

    /** 进程内缓存的最近一次解析结果，避免每次界面刷新都重新解析大字符串。 */
    private var cache: List<String>? = null

    /** 缓存对应的原始存储文本（用于判断缓存是否仍然有效）。 */
    private var cachedRaw: String? = null

    /* ============================ 对外接口（纯 KeyValueStore，可离线测试） ============================ */

    /** 追加一条（时间戳由本方法生成）。任何异常都被吞掉，不抛。 */
    fun record(store: KeyValueStore, event: String) = recordAt(store, System.currentTimeMillis(), event)

    /** 取全部（按时间正序）。任何异常都返回空列表，不抛。 */
    fun list(store: KeyValueStore): List<String> = try {
        synchronized(LOCK) {
            val raw = store.getString(KEY).orEmpty()
            val hit = cache
            if (hit != null && raw == cachedRaw) {
                hit
            } else {
                val parsed = parse(raw)
                cache = parsed
                cachedRaw = raw
                parsed
            }
        }
    } catch (t: Throwable) {
        emptyList()
    }

    /** 清空（写空串而不是删除键：统一「空日志」的表示，避免两种状态）。 */
    fun clear(store: KeyValueStore) {
        try {
            synchronized(LOCK) {
                store.putString(KEY, "")
                cache = emptyList()
                cachedRaw = ""
            }
        } catch (t: Throwable) {
            // 清空失败不影响主流程（界面层会给出提示）
        }
    }

    /** 与 [record] 相同，但允许注入时间（离线测试用）。 */
    fun recordAt(store: KeyValueStore, atMillis: Long, event: String) {
        try {
            val line = format(formatTime(atMillis), sanitize(event))
            synchronized(LOCK) {
                val lines = ArrayList(list(store))
                lines.add(line)
                val trimmed = if (lines.size > MAX_ENTRIES) lines.subList(lines.size - MAX_ENTRIES, lines.size) else lines
                val next = trimmed.toList()
                val text = next.joinToString("\n")
                store.putString(KEY, text)
                cache = next
                cachedRaw = text
            }
        } catch (t: Throwable) {
            // 日志写失败必须被吞掉：绝不影响认证/界面主流程
        }
    }

    /* ============================ 脱敏工具 ============================ */

    /**
     * 账户脱敏：**只保留前 3 位**，其余用 `…` 替代。
     *
     * 实现委托给 [AccountMask]（同包、零依赖文件）：那里的方法已被 JVM 离线测试真实编译并运行过
     * （证据：artifacts/logfix1/jvm-mask-test.txt），因此这里不再重复实现一份可能漂移的逻辑。
     *  - `19554537708` → `195…`
     *  - 不足 3 位（如 `ab`、空串）→ **原样返回**（不越界、不补位）
     */
    fun maskAccount(username: String): String = AccountMask.maskAccount(username)

    /** 把文本里所有 [secrets] 子串替换成 `***`（长度 >= 2 的才替换，避免单字符把文本打成星号）。 */
    fun redact(text: String, secrets: List<String>): String = AccountMask.redact(text, secrets)

    /**
     * 兜底脱敏（第三道防线）：把「看起来是密码字段」的值替换成 `***`，并把换行/制表符压成空格。
     *
     * 三道防线的分工：
     *  1. **调用点不传密码**（主防线，见 fix-report.md 的点位清单）；
     *  2. [recordWithSecrets]：调用点能拿到密码明文时，对已知密码做硬替换；
     *  3. 本方法：防止将来有人写出 `"password=" + pwd` 这类字符串拼接。
     *
     * 覆盖面（大小写不敏感）：`password` / `pwd` / `密码` 紧接 `=`、`:` 或 `：`（可带引号与空格）的取值。
     */
    fun sanitize(event: String): String {
        val masked = PASSWORD_PATTERN.replace(event) { m -> m.groupValues[1] + "=***" }
        val oneLine = masked.replace(Regex("[\\r\\n\\t]+"), " ")
        return if (oneLine.length > MAX_LINE_CHARS) oneLine.take(MAX_LINE_CHARS) + "…" else oneLine
    }

    /** 已知密码的硬替换版本：能拿到密码明文的调用点**应当**用这个而不是 [record]。 */
    fun recordWithSecrets(store: KeyValueStore, event: String, secrets: List<String>) =
        record(store, redact(event, secrets))

    /* ============================ 内部工具 ============================ */

    private fun parse(raw: String): List<String> =
        if (raw.isBlank()) emptyList() else raw.split("\n").filter { it.isNotEmpty() }

    /**
     * 行格式：`MM-dd HH:mm:ss 事件`（logfix2 任务 A 段：带日期，跨天可分辨）。
     *
     * 形参名 `hhmmss` 保持 logfix1 原样不改成 `stamp`：**冻结的离线核对 class 快照按同一份
     * Kotlin 元数据链接**，改名虽不影响 JVM 签名，但没有任何收益，一律不动（避免命名实参与
     * Metadata 层面的任何风险）。
     */
    fun format(hhmmss: String, event: String): String = "$hhmmss $event"

    /**
     * `MM-dd HH:mm:ss` 格式化（**系统本地时间**、24 小时制；纯 JVM，不依赖 Android DateFormat，便于离线核对）。
     *
     * 【logfix2 任务 A 段·修复】修复前是 `HH:mm:ss` 且**直接对毫秒取模**
     * （`((millis/1000) % 86400 + 86400) % 86400`），得到的是 **UTC 墙上时间**，没有加时区偏移 ——
     * 真机上比本地时间少 8 小时（用户实测：本地约 14:48，日志显示 02:48）。
     *
     * 现在用 [java.util.Calendar]（**默认时区 = 系统时区**）取 `HOUR_OF_DAY / MINUTE / SECOND`（24 小时制），
     * 并在前面补 `MM-dd` 日期：跨天时只看 `HH:mm:ss` 会把「昨天 02:48」与「今天 02:48」混为一谈。
     * [java.util.Calendar] 是 JDK 类，**不引入任何 Android 依赖**，本文件保持纯 JVM 可离线编译/运行。
     *
     * 离线证据（真实编译运行本文件）：artifacts/logfix2/jvm-time-test.txt。
     */
    fun formatTime(millis: Long): String {
        val cal = java.util.Calendar.getInstance()
        cal.timeInMillis = millis
        val date = two(cal.get(java.util.Calendar.MONTH) + 1) + "-" + two(cal.get(java.util.Calendar.DAY_OF_MONTH))
        val time = two(cal.get(java.util.Calendar.HOUR_OF_DAY)) + ":" +
            two(cal.get(java.util.Calendar.MINUTE)) + ":" + two(cal.get(java.util.Calendar.SECOND))
        return "$date $time"
    }

    private fun two(v: Int): String = if (v < 10) "0$v" else v.toString()

    /** 密码字段模式：`password` / `pwd` / `密码` + 分隔符（`=`/`:`/`：`）+ 值。 */
    private val PASSWORD_PATTERN = Regex(
        "(?i)(password|pwd|密码)\\s*[:：=]\\s*[\"']?([^\\s,;\"'，；]{1,128})",
        RegexOption.IGNORE_CASE
    )
}
