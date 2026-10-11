package top.ytu.srunautologin.clientcheck

/**
 * 认证客户端 / 编排 / UI 逻辑的核对逻辑（纯 Kotlin，无 JUnit 依赖）。
 *
 * 同一份代码被两处引用，避免两份实现漂移：
 *  - jvm-check-client 模块（离线运行，本机无 Gradle/SDK 时的验证通道）
 *  - app 单元测试（有 Gradle 时 `./gradlew :app:test`，包装成 JUnit 用例）
 */

/** 一条核对结果。 */
data class CheckResult(
    val id: String,
    val passed: Boolean,
    val detail: String
)

/** 核对集合执行器：逐条执行、捕获异常（异常即不通过），并汇总。 */
class CheckRunner {
    private val results = ArrayList<CheckResult>()

    fun check(id: String, block: () -> String) {
        val r = try {
            CheckResult(id, true, block())
        } catch (e: AssertionError) {
            CheckResult(id, false, "断言失败：${e.message}")
        } catch (e: Exception) {
            CheckResult(id, false, "异常：${e::class.java.name}: ${e.message}")
        }
        results.add(r)
        val tag = if (r.passed) "PASS" else "FAIL"
        println("[$tag] ${r.id} | ${r.detail}")
    }

    fun all(): List<CheckResult> = results.toList()

    fun failed(): List<CheckResult> = results.filter { !it.passed }

    fun require(condition: Boolean, message: String) {
        if (!condition) throw AssertionError(message)
    }

    fun requireEquals(expected: Any?, actual: Any?, what: String) {
        if (expected != actual) throw AssertionError("$what 期望 <$expected> 实际 <$actual>")
    }

    fun requireContains(haystack: String, needle: String, what: String) {
        if (!haystack.contains(needle)) throw AssertionError("$what 期望包含 <$needle>，实际：$haystack")
    }

    fun requireNotContains(haystack: String, needle: String, what: String) {
        if (haystack.contains(needle)) throw AssertionError("$what 期望不包含 <$needle>")
    }
}

/** 汇总输出（含逐条结论与总数）。 */
fun CheckRunner.report(title: String): String {
    val all = all()
    val failed = failed()
    val sb = StringBuilder()
    sb.appendLine("==== $title ====")
    sb.appendLine("总核对项：${all.size}；通过：${all.size - failed.size}；失败：${failed.size}")
    for (r in all) sb.appendLine("  [${if (r.passed) "PASS" else "FAIL"}] ${r.id} | ${r.detail}")
    if (failed.isNotEmpty()) {
        sb.appendLine("---- 失败明细 ----")
        for (r in failed) sb.appendLine("  FAIL ${r.id} | ${r.detail}")
    }
    return sb.toString()
}
