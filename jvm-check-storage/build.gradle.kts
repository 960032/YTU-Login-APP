// 目的：本机没有 Android SDK，`./gradlew :app:test` 无法运行。
// 本模块只编译 storage/ 与 net/ 两个**纯 JVM** 包 + verify-common-storage 的核对逻辑，
// 不引入任何第三方依赖（只用 Kotlin 标准库）。platform/ 包引用 Android SDK，必须排除。
// 有网络/SDK 时的复跑命令：./gradlew -p jvm-check-storage run
plugins {
    kotlin("jvm") version "2.2.21"
    application
}

sourceSets {
    main {
        kotlin.srcDir("../app/src/main/java")
        kotlin.srcDir("../verify-common-storage/src/main/kotlin")
        kotlin.exclude("**/platform/**")   // Android 边界层，离线环境无 android.jar
    }
}

application {
    mainClass.set("top.ytu.srunautologin.storagecheck.StorageCheckMainKt")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.named<JavaExec>("run") {
    args = listOf(java.io.File(projectDir.parentFile.parentFile, "android-storage/jvm-run-tmp").absolutePath)
}