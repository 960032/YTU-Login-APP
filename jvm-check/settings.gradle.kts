// 独立构建（与 android-app 的 settings 分开）：本模块只依赖 Kotlin/JVM 插件，不依赖 Android SDK。
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "srun-crypto-jvmcheck"
