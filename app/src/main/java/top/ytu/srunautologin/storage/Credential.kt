package top.ytu.srunautologin.storage

/**
 * 一条登录凭据。
 *
 * 字段口径（已冻结，来自上一任务裁决）：
 *  - label   ：用户自定义备注名，如「中国移动」；
 *  - carrier ：登录方式，取值 [Carrier.YTU]（"ytu"＝烟台大学）或 [Carrier.CMCC]（"cmcc"＝中国移动）；
 *  - acId    ：**必须是字符串** "5"。
 *
 * 本文件为纯 JVM 代码（不引用任何 Android API），可在无 Android SDK 的环境下编译与测试。
 */
data class Credential(
    val label: String,
    val username: String,
    val password: String,
    val carrier: String = Carrier.YTU,
    val acId: String = Carrier.AC_ID
) {
    init {
        require(label.isNotBlank()) { "label 不能为空" }
        require(Carrier.isSupported(carrier)) {
            "carrier 必须是 ${Carrier.YTU} 或 ${Carrier.CMCC}，实际为 $carrier"
        }
        require(acId == Carrier.AC_ID) {
            "acId 已冻结为字符串 \"${Carrier.AC_ID}\"，实际为 $acId"
        }
    }

    /** 日志安全表示：绝不包含 password（防止密码被拼进日志）。 */
    override fun toString(): String =
        "Credential(label=$label, username=$username, password=***, carrier=$carrier, acId=$acId)"
}

/** 登录方式常量与显示名。 */
object Carrier {
    const val YTU = "ytu"
    const val CMCC = "cmcc"

    /** 已冻结：本应用所有登录方式的 acId 均为字符串 "5"。 */
    const val AC_ID = "5"

    fun isSupported(value: String): Boolean = value == YTU || value == CMCC

    fun displayName(value: String): String = when (value) {
        YTU -> "烟台大学"
        CMCC -> "中国移动"
        else -> value
    }
}