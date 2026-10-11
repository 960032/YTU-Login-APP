package top.ytu.srunautologin.storagecheck

import java.io.File
import kotlin.system.exitProcess

/**
 * 离线核对运行器（纯 JVM，零第三方依赖）。
 *
 * 用法：java -cp <classes>;<kotlin-stdlib> top.ytu.srunautologin.storagecheck.StorageCheckMainKt <工作目录>
 * 退出码：0 = 全部通过；1 = 存在失败项。
 */
fun main(args: Array<String>) {
    val workDir = File(args.getOrElse(0) { "build/jvm-check-storage-tmp" })
    println("=== SrunAutoLogin 存储层 / WiFi 感知层 离线核对（纯 JVM，不依赖 Android SDK） ===")
    println("Java 版本: ${System.getProperty("java.version")}")
    println("OS: ${System.getProperty("os.name")} ${System.getProperty("os.version")}")
    println("工作目录: ${workDir.absolutePath}")
    println("核对对象: app/src/main/java/top/ytu/srunautologin/{storage,net} 的同一份源码")
    println()

    val items = StorageChecks.runAll(workDir)
    var passed = 0
    for (item in items) {
        if (item.passed) passed++
        println("[${if (item.passed) "PASS" else "FAIL"}] ${item.id} ${item.title}")
        println("        证据: ${item.evidence}")
    }

    val failed = items.filter { !it.passed }
    println()
    println("=== 汇总：共 ${items.size} 项，通过 $passed，失败 ${failed.size} ===")
    if (failed.isNotEmpty()) {
        failed.forEach { println("FAILED ${it.id}: ${it.evidence}") }
        exitProcess(1)
    }
    println("全部通过 → 退出码 0")
    exitProcess(0)
}