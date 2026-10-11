package top.ytu.srunautologin.crypto

import java.io.File
import kotlin.system.exitProcess

/**
 * 纯 JVM 向量核对运行器（**零第三方依赖**：只用 Kotlin 标准库 + java.io）。
 *
 * 为什么需要它：本机没有 Android SDK（也没有 Gradle 可解析的 JUnit 构件），
 * 因此 `./gradlew :app:test` 无法运行。本运行器把同一套源码
 * （app/src/main/.../SrunCrypto.kt + verify-common/.../VectorChecks.kt）编译成普通 JVM 字节码并真实执行，
 * 用同一份 testvectors/vectors.json 做逐字符核对。它**不是** JUnit，也不替代 JUnit；
 * 结论只说明 Kotlin 实现与 Node 基准是否逐字符一致。
 *
 * 用法：java -cp <classes>;<kotlin-stdlib.jar> top.ytu.srunautologin.crypto.VectorCheckKt <vectors.json 路径>
 * 退出码：0 = 全部通过；1 = 存在不一致；2 = 无法运行（向量文件缺失等）。
 */
fun main(args: Array<String>) {
    val path = args.firstOrNull() ?: "testvectors/vectors.json"
    val file = File(path)

    println("==== SrunCrypto 向量核对（纯 JVM，零第三方依赖）====")
    println("java.version   = " + System.getProperty("java.version"))
    println("java.home      = " + System.getProperty("java.home"))
    println("向量文件        = " + file.absolutePath + "  (" + file.length() + " bytes)")

    if (!file.isFile) {
        println("FAIL: 向量文件不存在，无法核对。")
        exitProcess(2)
    }

    val result = try {
        VectorChecks.run(file)
    } catch (t: Throwable) {
        println("FAIL: 核对过程抛出异常: " + t)
        t.printStackTrace(System.out)
        exitProcess(2)
    }

    println()
    println("---- 逐条结果 ----")
    for (c in result.cases) {
        val flag = if (c.ok) "PASS" else "FAIL"
        println("$flag | ${c.category} #${c.index} | ${c.label} | ${c.detail}")
    }

    println()
    println("---- 分类汇总 ----")
    for ((cat, pass, all) in result.perCategory()) {
        println("$cat: $pass/$all " + (if (pass == all) "PASS" else "FAIL"))
    }

    println()
    println("---- 总计 ----")
    println("用例总数 = ${result.total}，通过 = ${result.passed}，失败 = ${result.failures.size}")
    if (result.failures.isEmpty()) {
        println("结论：Kotlin 实现与 Node 基准逐字符一致（全部 ${result.total} 条向量通过）")
        println("退出码 = 0")
        exitProcess(0)
    } else {
        println("结论：存在 ${result.failures.size} 条不一致，见上方 FAIL 行")
        println("退出码 = 1")
        exitProcess(1)
    }
}
