import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val releaseKey = providers.environmentVariable("SRUN_KEYSTORE_FILE").orNull
val buildVersion = providers.gradleProperty("srunVersionCode").orElse("1792800000").get().toInt()
require(buildVersion in 1..2100000000)
android {
    namespace = "top.ytu.srunautologin"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = "top.ytu.srunautologin.secure"
        minSdk = 26
        targetSdk = 36
        versionCode = buildVersion
        versionName = "0.2.0"
    }
    signingConfigs {
        getByName("debug") {
            storeFile = rootProject.file(".local-signing/debug.keystore")
        }
        if (releaseKey != null) create("privateRelease") {
            storeFile = file(releaseKey)
            storePassword = providers.environmentVariable("SRUN_KEYSTORE_PASSWORD").get()
            keyAlias = providers.environmentVariable("SRUN_KEY_ALIAS").get()
            keyPassword = providers.environmentVariable("SRUN_KEY_PASSWORD").get()
            enableV1Signing = true
            enableV2Signing = true
        }
    }
    buildTypes {
        debug {
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
        }
        release {
            isDebuggable = false
            isMinifyEnabled = false
            if (releaseKey != null) signingConfig = signingConfigs.getByName("privateRelease")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets {
        getByName("test") {
            kotlin.srcDir("../verify-common/src/main/kotlin")
        }
    }
}
kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}
dependencies { testImplementation("junit:junit:4.13.2") }
val localDebugStore = rootProject.file(".local-signing/debug.keystore")
val ensureLocalDebugKeystore = tasks.register<Exec>("ensureLocalDebugKeystore") {
    onlyIf { !localDebugStore.exists() }
    doFirst { localDebugStore.parentFile.mkdirs() }
    val executable = if (System.getProperty("os.name").startsWith("Windows")) "keytool.exe" else "keytool"
    commandLine(File(System.getProperty("java.home"), "bin/$executable"),
        "-genkeypair", "-noprompt", "-keystore", localDebugStore.absolutePath,
        "-storetype", "JKS", "-alias", "androiddebugkey", "-storepass", "android", "-keypass", "android",
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", "-dname", "CN=Android Debug,O=Android,C=US")
}
tasks.matching { it.name == "validateSigningDebug" }.configureEach { dependsOn(ensureLocalDebugKeystore) }
