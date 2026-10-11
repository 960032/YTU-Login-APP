package top.ytu.srunautologin.clientcheck

import java.io.File

/**
 * 离线核对程序入口（纯 JVM，无 JUnit 依赖）。
 *
 * 用法：
 *   ClientCheckMainKt [android-app 项目根目录]
 *
 * 输出：逐条 PASS/FAIL + 汇总；退出码：0 = 全部通过，1 = 有失败项。
 */
fun main(args: Array<String>) {
    val appRoot = args.firstOrNull()?.let { File(it) } ?: File(".")

    println("================ 认证客户端 / 编排 / UI 纯逻辑 离线核对 ================")
    println("android-app 项目根目录：${appRoot.absolutePath}")
    println("Java：${System.getProperty("java.version")} @ ${System.getProperty("java.home")}")
    println("时间：${java.util.Date()}")

    val results = ClientChecks.runAll(appRoot)
    val failed = results.filter { !it.passed }
    println()
    println("------- 逐条结论 -------")
    for (x in results) {
        println("[${if (x.passed) "PASS" else "FAIL"}] ${x.id}")
        println("        ${x.detail}")
    }
    println()
    println("------- 源码/资源结构核对（B2/N4/B10） -------")
    val runner = CheckRunner()
    if (appRoot.isDirectory) {
        SourceChecks.run(runner, appRoot)
    } else {
        println("[SKIP] 未提供有效的 android-app 目录，跳过源码结构核对：${appRoot.absolutePath}")
    }
    val srcFailed = runner.failed()

    val total = results.size + runner.all().size
    val totalFailed = failed.size + srcFailed.size
    println()
    println("================ 汇总 ================")
    println("纯逻辑核对项：${results.size}，失败：${failed.size}")
    println("结构核对项：${runner.all().size}，失败：${srcFailed.size}")
    println("合计：$total 项，失败 $totalFailed 项")
    if (totalFailed == 0) {
        println("结论：全部通过")
        kotlin.system.exitProcess(0)
    } else {
        println("结论：存在失败项")
        for (x in failed + srcFailed) println("  FAIL ${x.id} | ${x.detail}")
        kotlin.system.exitProcess(1)
    }
}
