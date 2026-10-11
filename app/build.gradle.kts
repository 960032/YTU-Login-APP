plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "top.ytu.srunautologin"
    compileSdk = 36

    defaultConfig {
        applicationId = "top.ytu.srunautologin"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // 本任务不涉及设备端测试，故不声明 testInstrumentationRunner
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("test") {
            // 与 jvm-check 模块共用同一份核对逻辑（向量解析 + 逐字符比对），避免两份实现漂移
            kotlin.srcDir("../verify-common/src/main/kotlin")
            // 存储层/WiFi 层的核对逻辑（与 jvm-check-storage 共用同一份）
            kotlin.srcDir("../verify-common-storage/src/main/kotlin")
            // 认证客户端 / 编排 / UI 逻辑的核对逻辑（与 jvm-check-client 共用同一份）
            kotlin.srcDir("../verify-common-client/src/main/kotlin")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

// 零第三方运行时依赖：主源码只用 JDK（java.security / javax.crypto），
// 唯一的 testImplementation 是 JUnit 4（Android 单元测试标准测试库）。
dependencies {
    testImplementation("junit:junit:4.13.2")
}
