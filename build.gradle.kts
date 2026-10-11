// 根构建脚本：只声明插件版本，不 apply。
//
// 【版本组合（主选，需在 JDK 17 上工作）】
//   Gradle 9.4.0  —— 本机 ~/.gradle/wrapper/dists 已存在 gradle-9.4.0-bin（无网络也能用）；
//                     CI 端由 gradle/actions/setup-gradle 按本文件 + workflow 的版本号下载；
//   AGP 8.13.0    —— 8.x 线明确支持 JDK 17（AGP 9.x 要求 JDK 17+ 属于**未验证**，见 ci-notes.md）；
//   Kotlin 2.2.21 —— 本机 ~/.gradle/caches/modules-2 已缓存该版本 KGP。
//
// 版本可用 -P 覆盖（CI 的 workflow_dispatch 输入会传进来）：
//   gradle -PagpVersion=9.0.0 -PkotlinVersion=2.2.21 assembleDebug
val agpVersion: String = (findProperty("agpVersion") as String?) ?: "8.13.0"
val kotlinVersion: String = (findProperty("kotlinVersion") as String?) ?: "2.2.21"

plugins {
    id("com.android.application") version agpVersion apply false
    id("org.jetbrains.kotlin.android") version kotlinVersion apply false
}

