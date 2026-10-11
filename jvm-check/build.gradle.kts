// 目的：本机没有 Android SDK，`./gradlew :app:test` 无法运行。
// 本模块把 app/src/main 的实现源码与 verify-common 的核对逻辑当作**纯 JVM 源码**编译并运行，
// 不依赖 Android、不引入任何第三方依赖（只用 Kotlin 标准库）。
// 有网络时的复跑命令：./gradlew -p jvm-check run
plugins {
    kotlin("jvm") version "2.2.21"
    application
}

sourceSets {
    main {
        kotlin.srcDir("../app/src/main/java")
        kotlin.srcDir("../verify-common/src/main/kotlin")
        // storage/ 与 net/ 包是纯 JVM 代码，可一并编译；platform/ 包引用 Android SDK，必须排除。
        kotlin.exclude("**/platform/**")
    }
}

application {
    mainClass.set("top.ytu.srunautologin.crypto.VectorCheckKt")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.named<JavaExec>("run") {
    // 向量文件位于 android-app/testvectors/vectors.json（本模块目录的上级）
    val vectors = java.io.File(projectDir.parentFile, "testvectors/vectors.json")
    args = listOf(vectors.absolutePath)
}
