// SrunAutoLogin —— Gradle 设置文件（本任务的 Android 项目骨架）
// 生成环境说明：本机**没有 Android SDK**、没有网络，因此本骨架从未执行过 assemble；
// 真正执行过的验证是纯 JVM 的向量核对（见 artifacts/kotlin-crypto/build-log.txt）。
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "SrunAutoLogin"
include(":app")
