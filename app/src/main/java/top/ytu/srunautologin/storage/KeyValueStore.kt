package top.ytu.srunautologin.storage

import java.io.File

interface KeyValueStore {
    fun getString(key: String): String?
    fun putString(key: String, value: String)
    fun remove(key: String)
    fun keys(): Set<String>
    fun putAll(changes: Map<String, String?>) {
        StorageTransactions.withLock { changes.forEach { (key, value) ->
            if (value == null) remove(key) else putString(key, value)
        } }
    }
}

/** Serializes related reads/writes across repository instances in this process. */
object StorageTransactions {
    val monitor = Any()
    fun <T> withLock(block: () -> T): T = synchronized(monitor) { block() }
}

class InMemoryKeyValueStore : KeyValueStore {
    private val map = LinkedHashMap<String, String>()
    override fun getString(key: String): String? = map[key]
    override fun putString(key: String, value: String) { map[key] = value }
    override fun remove(key: String) { map.remove(key) }
    override fun keys(): Set<String> = LinkedHashSet(map.keys)
    override fun toString(): String = "InMemoryKeyValueStore(keys=${map.keys})"
}

class FileKeyValueStore(private val dir: File) : KeyValueStore {
    init {
        if (!dir.exists()) dir.mkdirs()
        require(dir.isDirectory) { "不是目录：${dir.absolutePath}" }
    }

    private fun fileOf(key: String): File {
        require(KEY_PATTERN.matches(key)) { "非法 key：$key" }
        return File(dir, "$key.kv")
    }

    override fun getString(key: String): String? {
        val f = fileOf(key)
        return if (f.isFile) f.readText(Charsets.UTF_8) else null
    }

    override fun putString(key: String, value: String) {
        fileOf(key).writeText(value, Charsets.UTF_8)
    }

    override fun remove(key: String) {
        val f = fileOf(key)
        if (f.isFile) f.delete()
    }

    override fun keys(): Set<String> =
        dir.listFiles().orEmpty()
            .filter { it.isFile && it.name.endsWith(SUFFIX) }
            .map { it.name.removeSuffix(SUFFIX) }
            .toSortedSet()

    companion object {
        private const val SUFFIX = ".kv"
        private val KEY_PATTERN = Regex("^[A-Za-z0-9_.-]{1,64}$")
    }
}

internal object TextEscaping {
    fun escape(raw: String): String {
        val sb = StringBuilder(raw.length + 8)
        for (ch in raw) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '\t' -> sb.append("\\t")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }

    fun unescape(raw: String): String {
        val sb = StringBuilder(raw.length)
        var i = 0
        while (i < raw.length) {
            val ch = raw[i]
            if (ch == '\\' && i + 1 < raw.length) {
                when (val next = raw[i + 1]) {
                    '\\' -> { sb.append('\\'); i += 2 }
                    't' -> { sb.append('\t'); i += 2 }
                    'n' -> { sb.append('\n'); i += 2 }
                    'r' -> { sb.append('\r'); i += 2 }
                    else -> { sb.append(next); i += 2 }
                }
            } else {
                sb.append(ch)
                i++
            }
        }
        return sb.toString()
    }

    fun joinFields(fields: List<String>): String = fields.joinToString("\t") { escape(it) }

    fun splitFields(line: String): List<String> = line.split("\t").map { unescape(it) }
}
