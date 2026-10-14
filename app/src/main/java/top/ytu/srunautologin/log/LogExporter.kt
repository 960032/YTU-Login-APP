package top.ytu.srunautologin.log

/**
 * 日志导出（logexport1 任务）：把内存里的日志文本渲染成 **Markdown 文件内容**。
 *
 * 【为什么单独一个文件、且刻意不 import Android 的类】
 * 本文件是**纯逻辑**（只用 [java.util.Calendar] 与 Kotlin 标准库），可以用 javac/java 在纯 JVM 上
 * 直接编译运行 → 导出内容「条数是否完整、是否含密码、Markdown 是否合法」这些判定都能**离线真跑**，
 * 而不是靠肉眼看代码（本机无真机，UI 路径无法离线验证，见 AGENTS.md §4）。
 * 证据：`artifacts/logexport1/jvm-export-test.txt`。
 *
 * Android 相关的一侧（选目录、写盘、Toast）留在 `ui/MainActivity.kt` 的 `exportLogs()` 里，
 * 两边通过 [buildMarkdown] / [fileName] / [displayPath] 三个纯函数衔接。
 *
 * 【隐私】导出**原样**输出 `AppLog` 里的条目 —— `AppLog.record` 写入前已经过
 * `sanitize()`（`password/pwd/密码` 的值替换为 `***`）与调用点的 `redact(secrets)` 硬替换，
 * 存储里本来就没有明文密码。本文件**不做**二次脱敏（避免把正常文本改花），
 * 但提供了 [containsSecretLike] 供离线测试断言「导出内容里搜不到密码字段」。
 */
object LogExporter {

    /** Markdown 文档标题（与 `strings.xml` 的 `log_export_title` 同义；纯逻辑侧不能读资源，故常量在此）。 */
    const val DOC_TITLE: String = "# 校园网自动登录 - 运行日志"

    /** 代码块围栏：日志正文用 `txt` 围栏包住，避免日志里的 `*`/`_`/`#` 被 Markdown 解释。 */
    private const val FENCE = "```"

    /**
     * 文件名：`srun-log-yyyyMMdd-HHmmss.md`。
     *
     * 时间格式与 [AppLog.formatTime]（`MM-dd HH:mm:ss`）风格一致（同样是本地时间、24 小时制、
     * 同样用 [Calendar]），只是**去掉分隔符并补上年份**，因为文件名里不适合出现空格与冒号
     * （部分文件管理器与 Windows 资源管理器不接受 `:`）。
     */
    fun fileName(millis: Long): String {
        val cal = java.util.Calendar.getInstance()
        cal.timeInMillis = millis
        val sb = StringBuilder("srun-log-")
        sb.append(cal.get(java.util.Calendar.YEAR))
        sb.append(two(cal.get(java.util.Calendar.MONTH) + 1))
        sb.append(two(cal.get(java.util.Calendar.DAY_OF_MONTH)))
        sb.append('-')
        sb.append(two(cal.get(java.util.Calendar.HOUR_OF_DAY)))
        sb.append(two(cal.get(java.util.Calendar.MINUTE)))
        sb.append(two(cal.get(java.util.Calendar.SECOND)))
        sb.append(".md")
        return sb.toString()
    }

    /**
     * 渲染 Markdown 全文。
     *
     * 结构（合法 Markdown：一级标题 + 无序列表元信息 + fenced code block）：
     * ```
     * # 校园网自动登录 - 运行日志
     *
     * - 导出时间：10-13 14:55:30
     * - 日志条数：168
     * - 应用版本：1234
     *
     * ```txt
     * <日志全文，每行一条>
     * ```
     * ```
     *
     * **条数必须完整**：本函数逐条写入 [lines]，不做任何截断/抽样（界面渲染上限
     * `LOG_RENDER_LIMIT=400` 只管屏幕，导出与「复制全部」一样取**全量 1000 条**）。
     *
     * @param lines   日志条目（`AppLog.list` 的返回值，已脱敏）
     * @param exportedAtMillis 导出时刻（用于文件名同款时间戳；由调用方传入便于离线测试）
     * @param versionCode 应用版本号（`PackageInfo.versionCode`）；取不到时传 0，显示 `未知`
     */
    fun buildMarkdown(lines: List<String>, exportedAtMillis: Long, versionCode: Int = 0): String {
        val sb = StringBuilder()
        sb.append(DOC_TITLE).append('\n').append('\n')
        sb.append("- 导出时间：").append(AppLog.formatTime(exportedAtMillis)).append('\n')
        sb.append("- 日志条数：").append(lines.size).append('\n')
        sb.append("- 应用版本：").append(if (versionCode > 0) versionCode.toString() else "未知").append('\n')
        sb.append('\n')
        sb.append(FENCE).append("txt").append('\n')
        for (line in lines) sb.append(line).append('\n')
        sb.append(FENCE).append('\n')
        return sb.toString()
    }

    /** 「导出时间」单独一行时的展示值（与 [buildMarkdown] 内使用的格式完全一致）。 */
    fun timestamp(millis: Long): String = AppLog.formatTime(millis)

    /**
     * 把绝对路径折成便于 Toast 阅读的两行展示（目录一行、文件名一行）。
     *
     * 用途：完整路径很长（`/storage/emulated/0/Android/data/<pkg>/files/srun-log-….md`），
     * 单行 Toast 会被系统截断；拆成两行后用户仍能看到**逐字完整**的目录与文件名。
     */
    fun displayPath(absolutePath: String): Pair<String, String> {
        val idx = absolutePath.lastIndexOf('/')
        return if (idx <= 0) {
            absolutePath to ""
        } else {
            absolutePath.substring(0, idx) to absolutePath.substring(idx + 1)
        }
    }

    /**
     * 粗判「文本里是否出现疑似**未脱敏**的密码赋值」——**只给离线测试用**的断言帮手。
     *
     * 与 [AppLog.sanitize] 的 `PASSWORD_PATTERN` 同义（`password/pwd/密码` + `=`/`:`/`：` + 值），
     * 但**排除脱敏后的占位符 `***`**：`AppLog.sanitize` 自己产出的就是 `password=***`，
     * 若把 `***` 也算命中，本守卫会在「正常脱敏过的日志」上误报（实现过程中实测踩到，
     * 见 artifacts/logexport1/fix-report.md §6 的 F2/P4 两处**测试自身**缺陷）。
     * 判定改为「存在某个密码字段，其取值的**非星号部分**长度 >= 1」。
     */
    fun containsSecretLike(text: String): Boolean =
        PASSWORD_PATTERN.findAll(text).any { m ->
            val value = m.groupValues[2]
            value.replace("*", "").replace("…", "").isNotEmpty()
        }

    private val PASSWORD_PATTERN = Regex(
        "(?i)(password|pwd|密码)\\s*[:：=]\\s*[\"']?([^\\s,;\"'，；]{1,128})",
        RegexOption.IGNORE_CASE
    )

    private fun two(v: Int): String = if (v < 10) "0$v" else v.toString()
}
