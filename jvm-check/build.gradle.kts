plugins {
    kotlin("jvm") version "2.2.21"
    application
}

sourceSets {
    main {
        kotlin.srcDir("../app/src/main/java")
        kotlin.srcDir("../verify-common/src/main/kotlin")
        kotlin.exclude("**/platform/**")
        kotlin.exclude("**/App.kt")
        kotlin.exclude("**/ui/MainActivity.kt")
        kotlin.exclude("**/work/AuthJobService.kt")
        kotlin.exclude("**/work/AuthScheduler.kt")
        kotlin.exclude("**/work/AuthWorkWiring.kt")
        kotlin.exclude("**/work/AutoLoginController.kt")
        kotlin.exclude("**/work/BootAndNetworkReceiver.kt")
        kotlin.exclude("**/work/MorningAuthForegroundService.kt")
        kotlin.exclude("**/work/MorningAuthRuntime.kt")
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
    val vectors = java.io.File(projectDir.parentFile, "testvectors/vectors.json")
    args = listOf(vectors.absolutePath)
}
