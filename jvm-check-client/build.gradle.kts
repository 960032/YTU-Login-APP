plugins {
    kotlin("jvm") version "2.2.21"
    application
}

sourceSets {
    main {
        kotlin.srcDir("../app/src/main/java")
        kotlin.srcDir("../verify-common-client/src/main/kotlin")
        kotlin.exclude("**/ui/MainActivity.kt")
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
    mainClass.set("top.ytu.srunautologin.clientcheck.ClientCheckMainKt")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
