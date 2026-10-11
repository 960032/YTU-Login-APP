// 目的：本机没有 Android SDK、无网络，`./gradlew :app:test` 无法运行。
// 本模块只编译 auth/ + flow/ + ui/ 三个**纯 JVM** 包（ui 包中只有 MainActivity 引用 Android SDK，
// 必须在下方 exclude）+ crypto/ 与 storage/net 的纯逻辑部分 + verify-common-client 的核对逻辑，
// 不引入任何第三方依赖（只用 Kotlin 标准库）。
// 有网络/SDK 时的复跑命令：./gradlew -p jvm-check-client run --args="<android-app 绝对路径>"
plugins {
    kotlin("jvm") version "2.2.21"
    application
}

sourceSets {
    main {
        kotlin.srcDir("../app/src/main/java")
        kotlin.srcDir("../verify-common-client/src/main/kotlin")
        // 只排除真正的 Android 边界层：Activity/View 绑定与 platform 装配。
        kotlin.exclude("**/ui/MainActivity.kt")
        kotlin.exclude("**/platform/**")
    }
}

application {
    mainClass.set("top.ytu.srunautologin.clientcheck.ClientCheckMainKt")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
