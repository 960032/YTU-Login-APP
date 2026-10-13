package top.ytu.srunautologin.log

/**
 * 账户脱敏工具（logfix1 任务 A 段）。
 *
 * 【为什么单独一个文件】这里的方法**不依赖任何 Android / KeyValueStore**，
 * 因此可以用 Gradle 内嵌的 `kotlin-compiler-embeddable` 在 JVM 上**真实编译并运行**
 * （离线证据：artifacts/logfix1/jvm-mask-test.txt），而不是只有「源码看着对」。
 *
 * 用户已确认的隐私决策：
 *  - 日志里账户**只记前 3 位**（如 `19554537708` → `195…`）；
 *  - 不足 3 位**原样返回**（不越界、不补位）；
 *  - **绝不记密码**（[redact] 对已知密码做硬替换；[AppLog.sanitize] 做兜底字段脱敏）。
 */
object AccountMask {

    /** 脱敏占位后缀：U+2026 单个省略号字符（`195…`）。 */
    const val ELLIPSIS: String = "…"

    /**
     * 账户脱敏：只保留前 3 位，其余用 [ELLIPSIS] 替代。
     *
     *  - `19554537708` → `195…`
     *  - `ab`（不足 3 位）→ `ab`（原样）
     *  - `""`（空串）→ `""`（不崩）
     *  - 前后空白先 trim（界面输入常见）
     *
     * 本方法只做截断与拼接，不接触密码。注意 Kotlin 非空参数约定：
     * 传 null 会在调用处抛 NPE —— 调用方一律传 `credential.username`（非空）或 `orEmpty()` 后的值。
     */
    fun maskAccount(username: String): String {
        val s = username.trim()
        if (s.length <= 3) return s
        return s.substring(0, 3) + ELLIPSIS
    }

    /** 把文本里所有 [secrets] 子串替换成 `***`（长度 >= 2 的才替换，避免单字符把文本打成星号）。 */
    fun redact(text: String, secrets: List<String>): String {
        var out = text
        for (secret in secrets) {
            if (secret.length < 2) continue
            out = out.replace(secret, "***")
        }
        return out
    }
}
