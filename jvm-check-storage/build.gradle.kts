plugins {
    kotlin("jvm") version "2.2.21"
    application
}

sourceSets {
    main {
        kotlin.srcDir("../app/src/main/java")
        kotlin.srcDir("../verify-common-storage/src/main/kotlin")
        kotlin.exclude("**/platform/**")
        kotlin.exclude("**/App.kt")
        kotlin.exclude("**/ui/MainActivity.kt")
        kotlin.exclude("**/work/AuthJobService.kt")
        kotlin.exclude("**/work/AuthScheduler.kt")
        kotlin.exclude("**/work/AuthWorkWiring.kt")
        kotlin.exclude("**/work/AutoLoginController.kt")
        kotlin.exclude("**/work/BootAndNetworkReceiver.kt")
        kotlin.exclude("**/work/MorningAuthForegroundService.kt")
        kotlin.exclude("**/work/MorningAuthRuntime.kt")   // Android 边界层，离线环境无 android.jar
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