package top.ytu.srunautologin.log

object AccountMask {

    const val ELLIPSIS: String = "…"

    fun maskAccount(username: String): String {
        val s = username.trim()
        if (s.isEmpty()) return ""
        if (s.length <= 3) return "***"
        return s.substring(0, 3) + ELLIPSIS
    }

    /** Redact longest secrets first, including one-character passwords. */
    fun redact(text: String, secrets: List<String>): String {
        var out = text
        val forms = secrets.filter(String::isNotEmpty).flatMap { secret ->
            val encoded = java.net.URLEncoder.encode(secret, "UTF-8")
            listOf(secret, encoded, encoded.replace("+", "%20"),
                secret.replace("\\", "\\\\").replace("\"", "\\\""))
        }
        for (secret in forms.distinct().sortedByDescending(String::length)) {
            out = out.replace(secret, "***")
        }
        return out
    }
}
