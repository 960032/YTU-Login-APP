package top.ytu.srunautologin.auth

/**
 * 极简 JSON 解析器 + JSONP 剥壳（纯 JVM、零第三方依赖、不依赖 Android 的 org.json）。
 *
 * 之所以自写而不依赖 org.json：本包必须在无 Android SDK 的机器上离线编译运行以接受验收；
 * Android 端同样可用（org.json 只是可用选项，不是必须）。
 */
sealed interface JsonValue {
    /** JSON 对象；键顺序按出现顺序保留。 */
    data class Obj(val entries: Map<String, JsonValue>) : JsonValue {
        operator fun get(key: String): JsonValue? = entries[key]
        fun keys(): Set<String> = entries.keys
    }

    /** JSON 字符串（已解转义）。 */
    data class Str(val value: String) : JsonValue

    /** JSON 数字（保留原始字面量，便于逐字符比对）。 */
    data class Num(val raw: String) : JsonValue {
        fun toLongOrNull(): Long? = raw.toLongOrNull()
    }

    /** JSON 布尔。 */
    data class Bool(val value: Boolean) : JsonValue

    /** JSON null。 */
    data object Null : JsonValue

    /** JSON 数组。 */
    data class Arr(val items: List<JsonValue>) : JsonValue

    /** 便于展示的字符串化：字符串返回值本身，数字/布尔/null 返回字面量，复合结构返回紧凑文本。 */
    fun str(): String? = when (this) {
        is Str -> value
        is Num -> raw
        is Bool -> value.toString()
        Null -> null
        is Obj, is Arr -> null
    }
}

/** JSON 文本解析器：严格语法 + 中文错误信息，便于诊断。 */
object SrunJson {

    fun parse(text: String): JsonValue {
        val p = Parser(text)
        p.skipWs()
        val v = p.parseValue()
        p.skipWs()
        if (!p.atEnd()) throw JsonSyntaxException("JSON 顶层结构之后存在多余字符（位置 ${p.pos}）")
        return v
    }

    private class JsonSyntaxException(message: String) : IllegalArgumentException(message)

    private class Parser(private val s: String) {
        var pos = 0

        fun atEnd(): Boolean = pos >= s.length

        fun skipWs() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        fun parseValue(): JsonValue {
            if (atEnd()) err("输入意外结束")
            return when (val c = s[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonValue.Str(parseString())
                't' -> parseKeyword("true", JsonValue.Bool(true))
                'f' -> parseKeyword("false", JsonValue.Bool(false))
                'n' -> parseKeyword("null", JsonValue.Null)
                else -> if (c == '-' || c in '0'..'9') parseNumber() else err("非法字符 '$c'")
            }
        }

        private fun parseObject(): JsonValue.Obj {
            expect('{')
            val map = LinkedHashMap<String, JsonValue>()
            skipWs()
            if (peek() == '}') {
                pos++
                return JsonValue.Obj(map)
            }
            while (true) {
                skipWs()
                if (peek() != '"') err("对象键必须是字符串")
                val key = parseString()
                skipWs()
                expect(':')
                skipWs()
                map[key] = parseValue()
                skipWs()
                when (peek()) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return JsonValue.Obj(map)
                    }
                    else -> err("对象成员之后期望 ',' 或 '}'")
                }
            }
        }

        private fun parseArray(): JsonValue.Arr {
            expect('[')
            val items = ArrayList<JsonValue>()
            skipWs()
            if (peek() == ']') {
                pos++
                return JsonValue.Arr(items)
            }
            while (true) {
                skipWs()
                items.add(parseValue())
                skipWs()
                when (peek()) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return JsonValue.Arr(items)
                    }
                    else -> err("数组元素之后期望 ',' 或 ']'")
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                if (atEnd()) err("字符串未闭合")
                val c = s[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (atEnd()) err("转义序列未完成")
                        val e = s[pos++]
                        when (e) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) err("\\u 转义不足 4 位")
                                val hex = s.substring(pos, pos + 4)
                                val code = hex.toIntOrNull(16) ?: err("\\u 转义非法：$hex")
                                pos += 4
                                sb.append(code.toChar())
                            }
                            else -> err("非法转义 '\\$e'")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun parseNumber(): JsonValue.Num {
            val start = pos
            if (peek() == '-') pos++
            while (!atEnd() && s[pos] in '0'..'9') pos++
            if (peek() == '.') {
                pos++
                while (!atEnd() && s[pos] in '0'..'9') pos++
            }
            if (peek() == 'e' || peek() == 'E') {
                pos++
                if (peek() == '+' || peek() == '-') pos++
                while (!atEnd() && s[pos] in '0'..'9') pos++
            }
            if (pos == start) err("数字字面量为空")
            return JsonValue.Num(s.substring(start, pos))
        }

        private fun parseKeyword(word: String, value: JsonValue): JsonValue {
            if (!s.startsWith(word, pos)) err("非法字面量，期望 $word")
            pos += word.length
            return value
        }

        private fun peek(): Char = if (atEnd()) '\u0000' else s[pos]

        private fun expect(c: Char) {
            if (atEnd() || s[pos] != c) err("期望 '$c'")
            pos++
        }

        private fun err(message: String): Nothing =
            throw JsonSyntaxException("$message（位置 $pos，片段：${snippet()}）")

        private fun snippet(): String =
            s.substring(pos, minOf(s.length, pos + 40)).replace('\n', ' ').replace('\r', ' ')
    }
}

/**
 * JSONP 剥壳 + 字段读取（纯逻辑）。容错口径逐字对齐参考实现 stripJsonp：
 *  - 允许首尾空白；
 *  - 去掉 UTF-8 BOM（\uFEFF）与 XSSI 前缀 `)]}',`；
 *  - 已是裸 JSON（以 { 或 [ 开头）时原样返回；
 *  - 形如 `callback({...})` / `window.cb({...});` 时取**第一个 '('** 与**最后一个 ')'** 之间的内容；
 *  - 找不到括号时原样返回，交给 JSON 解析器报错。
 */
object Jsonp {

    fun strip(body: String): String {
        var s = body.trim()
        if (s.startsWith("\uFEFF")) s = s.substring(1).trim()
        // XSSI 前缀：)]}', 或 )]}'
        if (s.startsWith(")]}")) {
            val idx = s.indexOf('\'')
            s = if (idx >= 0) s.substring(idx + 1).trim() else s.substring(4).trim()
        }
        if (s.startsWith("{") || s.startsWith("[")) return s
        val open = s.indexOf('(')
        val close = s.lastIndexOf(')')
        if (open != -1 && close > open) return s.substring(open + 1, close).trim()
        return s
    }

    fun parse(body: String): JsonValue = SrunJson.parse(strip(body))

    /** 安全版：解析失败返回 null（调用方负责转成 E_PARSE）。 */
    fun tryParse(body: String): JsonValue? = try {
        parse(body)
    } catch (e: Exception) {
        null
    }
}

/**
 * 两个接口响应的字段读取器（纯逻辑）。
 *
 * get_challenge  → challenge / client_ip / error
 * srun_portal    → error / ecode / error_msg / ploy_msg / res / sip / srunacct
 */
object SrunResponseReader {

    /** 服务端业务码统一取法（参考实现 msgOf / ecode 口径）。 */
    fun errorOf(root: JsonValue.Obj): String? = root["error"]?.str()

    fun ecodeOf(root: JsonValue.Obj): String? =
        root["ecode"]?.str() ?: root["error_code"]?.str()

    /** 人读信息：error_msg 优先，其次 ploy_msg（E0000 前缀视为无信息）。 */
    fun messageOf(root: JsonValue.Obj): String? {
        val err = root["error_msg"]?.str()
        if (!err.isNullOrBlank() && err != "ok") return err
        val ploy = root["ploy_msg"]?.str()
        if (!ploy.isNullOrBlank() && !ploy.startsWith("E0000")) return ploy
        return null
    }

    fun challengeOf(root: JsonValue.Obj): String? = root["challenge"]?.str()

    fun clientIpOf(root: JsonValue.Obj): String? {
        val ip = root["client_ip"]?.str()?.trim()
        return if (ip.isNullOrEmpty()) null else ip
    }

    /** 业务是否成功：**只认 error == "ok"**。 */
    fun isOk(root: JsonValue.Obj): Boolean = root["error"]?.str() == SrunProtocol.OK
}
