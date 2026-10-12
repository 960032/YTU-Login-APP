// =====================================================================================
// 【签名与版本号策略（signfix1 任务）】
//   背景（用户真机反馈）：覆盖安装失败。两个已实测确认的原因：
//     1) 版本号前后一致（versionCode 恒为 1 / versionName 恒为 "0.1.0"）
//     2) 前后签名不一致 —— apksigner verify --print-certs 显示每版 APK 的签名证书 SHA-256 都不同
//        实测：dist\srun-autologin-1012-1020.apk → e7b1161eb377ea416c52760f1a297089611bb47d12994e29568ac4b350913bfb
//              dist\srun-autologin-1012-1001.apk → 3444a9a282d6a00fc4617a43926a8af4a18eef31f5304e89c7baf1f5a7580929
//   根因：tools/build-local.ps1 把 debug keystore 放在 $env:TEMP\srun-build\debug.keystore，
//         而 DSH 每次 pwsh 调用的临时目录都不同（dsh-WmDqvJ / dsh-rfBBfE ...）
//         → 每次都生成一把新钥匙 → 每版 APK 签名都不同 → Android 拒绝覆盖安装。
//   对策：签名与版本号都在本文件里显式声明，钥匙固定存放在仓库根的 keystore/debug.keystore。
// =====================================================================================

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// 【版本号：每次构建自动递增，不再硬编码】
//   取值 = 当前 Unix 秒级时间戳。
//   容量口径（修正）：Int 上限 2147483647 对应 2038-01-19，而不是 2106 年；2106 是 UInt 的口径。
//         故这里的有效期按 2038 口径说明，到期前需换成 longVersionCode 一类方案。
//   为什么用它：单调递增、无需额外状态文件、不依赖 git（本工作区根不是 git 仓库）；
//         且远大于旧版的 versionCode = 1 —— Android 的升级判定要求新 versionCode 严格更大。
//   代价（已记录、未处理）：秒级时间戳使构建不再可复现（同一份源码两次构建产物内容不同）。
//         接受该代价，是为了彻底消除「忘了改版本号导致无法覆盖安装」这一类故障。
val autoVersionCode: Int = (System.currentTimeMillis() / 1000L).toInt()

// 【版本名：人类可读 + 唯一】
//   "0.1." + versionCode：与 versionCode 一一对应，肉眼可判先后、永不相同，
//   且不像纯时间戳那样难读。例：versionCode=1786507071 → versionName="0.1.1786507071"。
val autoVersionName: String = "0.1.$autoVersionCode"

// 【签名：两层来源，优先级 = 环境变量/gradle 属性 > 项目内固定 keystore】
//   第 1 层（为将来的正式发布预留）：SRUN_KEYSTORE_FILE / SRUN_KEYSTORE_PASSWORD /
//            SRUN_KEY_PASSWORD / SRUN_KEY_ALIAS，可由 CI 用 GitHub Secrets 注入 release key，
//            届时不需要改动本文件。
//   第 2 层（本地默认）：仓库根的 keystore/debug.keystore —— 固定路径、跨会话稳定。
//            用 rootProject.file(...) 定位，而不是相对 app/ 模块定位：
//            本地构建脚本把源码 robocopy 到 artifacts/build-local 之后，keystore/ 相对**新根**
//            同样是 keystore/，因此两种布局都成立。
//   为什么这里的口令是明文默认值 android / android / androiddebugkey：
//            这是 Android debug keystore 全世界的通行默认口令，debug key 本身不保护任何敏感信息
//            （它只用于本机/CI 自签名，签名后的 APK 依旧是 debuggable）。
//            正式 release 签名请走第 1 层环境变量，不要把 release 口令写进本文件。
val envKeystoreFile: String? = providers.environmentVariable("SRUN_KEYSTORE_FILE").orNull
val projectDebugKeystoreFile = rootProject.file("keystore/debug.keystore")
val projectDebugKeystoreExists: Boolean = projectDebugKeystoreFile.exists()

android {
    namespace = "top.ytu.srunautologin"
    compileSdk = 36

    signingConfigs {
        create("srunDebug") {
            if (envKeystoreFile != null) {
                storeFile = file(envKeystoreFile)
            } else if (projectDebugKeystoreExists) {
                storeFile = projectDebugKeystoreFile
            } else {
                // 兜底：两者都不存在时仍保持构建可用（AGP 会去用默认 debug keystore）。
                // 本仓库已提交 keystore/debug.keystore，正常不会走到这一支。
                storeFile = null
            }
            storePassword = providers.environmentVariable("SRUN_KEYSTORE_PASSWORD").getOrElse("android")
            keyAlias = providers.environmentVariable("SRUN_KEY_ALIAS").getOrElse("androiddebugkey")
            keyPassword = providers.environmentVariable("SRUN_KEY_PASSWORD").getOrElse("android")
            enableV1Signing = true
            enableV2Signing = true
        }
    }

    defaultConfig {
        applicationId = "top.ytu.srunautologin"
        minSdk = 26
        targetSdk = 36
        versionCode = autoVersionCode
        versionName = autoVersionName
        // 本任务不涉及设备端测试，故不声明 testInstrumentationRunner
    }

    buildTypes {
        debug {
            // 显式指定签名：不再依赖 AGP 的默认 debug keystore（它随机器/用户目录变化）。
            // 注意：本机命令行构建会额外注入 android.injected.signing.*，AGP 允许该注入覆盖此处的明文口令；
            // 两处指向**同一把钥匙**（仓库根 keystore/debug.keystore），因此结果唯一。
            signingConfig = signingConfigs.getByName("srunDebug")
        }
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
