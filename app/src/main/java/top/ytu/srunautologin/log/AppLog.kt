package top.ytu.srunautologin.log

import top.ytu.srunautologin.storage.KeyValueStore

object AppLog {

    const val MAX_ENTRIES: Int = 1000

    const val KEY: String = "srun_log_v1"

    private const val MAX_LINE_CHARS: Int = 300

    private val LOCK = Any()

    private var cache: List<String>? = null

    private var cachedRaw: String? = null

    fun record(store: KeyValueStore, event: String) = recordAt(store, System.currentTimeMillis(), event)

    fun list(store: KeyValueStore): List<String> = try {
        synchronized(LOCK) {
            val raw = store.getString(KEY).orEmpty()
            val hit = cache
            if (hit != null && raw == cachedRaw) {
                hit
            } else {
                val parsed = parse(raw)
                cache = parsed
                cachedRaw = raw
                parsed
            }
        }
    } catch (t: Throwable) {
        emptyList()
    }

    fun clear(store: KeyValueStore) {
        try {
            synchronized(LOCK) {
                store.putString(KEY, "")
                cache = emptyList()
                cachedRaw = ""
            }
        } catch (t: Throwable) {
        }
    }

    fun recordAt(store: KeyValueStore, atMillis: Long, event: String) {
        try {
            val line = format(formatTime(atMillis), sanitize(event))
            synchronized(LOCK) {
                val lines = ArrayList(list(store))
                lines.add(line)
                val trimmed = if (lines.size > MAX_ENTRIES) lines.subList(lines.size - MAX_ENTRIES, lines.size) else lines
                val next = trimmed.toList()
                val text = next.joinToString("\n")
                store.putString(KEY, text)
                cache = next
                cachedRaw = text
            }
        } catch (t: Throwable) {
        }
    }

    fun maskAccount(username: String): String = AccountMask.maskAccount(username)

    fun redact(text: String, secrets: List<String>): String = AccountMask.redact(text, secrets)

    fun sanitize(event: String): String {
        val withoutQueries = Regex("https?://[^\\s<>\"]+", RegexOption.IGNORE_CASE).replace(event) { m -> m.value.substringBefore('?').substringBefore('#') }
        val masked = PASSWORD_PATTERN.replace(withoutQueries) { m -> m.groupValues[1] + "=***" }
        val oneLine = masked.replace(Regex("[\\r\\n\\t]+"), " ")
        return if (oneLine.length > MAX_LINE_CHARS) oneLine.take(MAX_LINE_CHARS) + "…" else oneLine
    }

    fun recordWithSecrets(store: KeyValueStore, event: String, secrets: List<String>) =
        record(store, redact(event, secrets))

    private fun parse(raw: String): List<String> =
        if (raw.isBlank()) emptyList() else raw.split("\n").filter { it.isNotEmpty() }

    fun format(hhmmss: String, event: String): String = "$hhmmss $event"

    fun formatTime(millis: Long): String {
        val cal = java.util.Calendar.getInstance()
        cal.timeInMillis = millis
        val date = two(cal.get(java.util.Calendar.MONTH) + 1) + "-" + two(cal.get(java.util.Calendar.DAY_OF_MONTH))
        val time = two(cal.get(java.util.Calendar.HOUR_OF_DAY)) + ":" +
            two(cal.get(java.util.Calendar.MINUTE)) + ":" + two(cal.get(java.util.Calendar.SECOND))
        return "$date $time"
    }

    private fun two(v: Int): String = if (v < 10) "0$v" else v.toString()

    private val PASSWORD_PATTERN = Regex(
        "(?i)(password|pwd|密码|info|chksum|challenge|token|username)[\"']?\\s*[:：=]\\s*[\"']?([^\\s,;\"'，；&]+)",
        RegexOption.IGNORE_CASE
    )
}
