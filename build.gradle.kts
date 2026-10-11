// 根构建脚本：只声明插件版本，不 apply。
//
// 【为什么这里的版本必须是字面量，不能写成变量】
//   Kotlin DSL 对 plugins {} 块做**编译期特殊处理**：块内的插件坐标与 version 必须是常量字面量。
//   一旦引用变量（哪怕是块外定义的 val agpVersion），脚本编译就会失败：
//     e: build.gradle.kts:15:43: Unresolved reference: agpVersion
//   这是 2026-06 云端构建首次运行的**真实失败原因**（完整日志见 artifacts/android-ci/ci-notes.md 第 0.5 节）。
//   所以本文件的版本**硬编码**，`-PagpVersion` / `-PkotlinVersion` 这种注入方式在本工程中不可用（已从 workflow 移除）。
//
// 【版本组合（主选，需在 JDK 17 上工作）】
//   Gradle 8.13   —— CI 端由 gradle/actions/setup-gradle 按 workflow 的 GRADLE_VERSION 下载；
//   AGP 8.13.0    —— 8.x 线明确支持 JDK 17；官方要求的最低 Gradle 见 ci-notes.md 第 2 节；
//   Kotlin 2.2.21 —— 与 workflow 的 KOTLIN_VERSION 一致。
//
// 【怎么换版本】改下面的 version 字面量 + 同步改 gradle.properties 的版本注释 + workflow 的 env。
//   三处必须同时改，改完对照 artifacts/android-ci/ci-notes.md 第 2 节的对照表。
plugins {
    id("com.android.application") version "8.13.0" apply false
    id("org.jetbrains.kotlin.android") version "2.2.21" apply false
}

