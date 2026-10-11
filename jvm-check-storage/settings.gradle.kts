// 独立构建（与上级 Android 工程解耦）：本机没有 Android SDK / 网络，Gradle 无法跑 Android 单元测试。
// 本模块把 storage/ 与 net/ 两个包当作**纯 JVM 源码**编译并运行离线核对。
rootProject.name = "jvm-check-storage"