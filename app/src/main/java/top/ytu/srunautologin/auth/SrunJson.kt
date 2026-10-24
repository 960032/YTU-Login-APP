package top.ytu.srunautologin.auth

sealed interface JsonValue {
    data class Obj(val entries: Map<String, JsonValue>) : JsonValue {
        operator fun get(key: String): JsonValue? = entries[key]
        fun keys(): Set<String> = entries.keys
    }

    data class Str(val value: String) : JsonValue

    data class Num(val raw: String) : JsonValue {
        fun toLongOrNull(): Long? = raw.toLongOrNull()
    }

    data class Bool(val value: Boolean) : JsonValue

    /** JSON null。 */
    data object Null : JsonValue

    data class Arr(val items: List<JsonValue>) : JsonValue

    fun str(): String? = when (this) {
        is Str -> value
        is Num -> raw
        is Bool -> value.toString()
        Null -> null
        is Obj, is Arr -> null
    }
}

object SrunJson {

    fun parse(text: String): JsonValue {
        require(text.length <= 262144) { "JSON 响应过长" }
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
        private var depth = 0
        private var nodes = 0

        fun atEnd(): Boolean = pos >= s.length

        fun skipWs() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        fun parseValue(): JsonValue {
            if (atEnd()) err("输入意外结束")
            if (++nodes > 10000 || ++depth > 32) err("JSON 结构超过限制")
            return try { when (val c = s[pos]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> JsonValue.Str(parseString())
                't' -> parseKeyword("true", JsonValue.Bool(true))
                'f' -> parseKeyword("false", JsonValue.Bool(false))
                'n' -> parseKeyword("null", JsonValue.Null)
                else -> if (c == '-' || c in '0'..'9') parseNumber() else err("非法字符 '$c'")
            } } finally { depth-- }
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
                if (map.containsKey(key)) err("JSON 对象包含重复字段")
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
                    c < ' ' -> err("JSON 字符串包含控制字符")
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
            val raw = s.substring(start, pos)
            if (!Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?").matches(raw)) err("数字格式无效")
            return JsonValue.Num(raw)
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
            throw JsonSyntaxException("$message（位置 $pos）")

        private fun snippet(): String =
            s.substring(pos, minOf(s.length, pos + 40)).replace('\n', ' ').replace('\r', ' ')
    }
}

object Jsonp {

    fun strip(body: String): String {
        var s = body.trim()
        if (s.startsWith("\uFEFF")) s = s.substring(1).trim()
        if (s.startsWith(")]}")) {
            val idx = s.indexOf('\'')
            s = if (idx >= 0) s.substring(idx + 1).trim() else s.substring(4).trim()
        }
        if (s.startsWith("{") || s.startsWith("[")) return s
        val open = s.indexOf('(')
        val close = s.lastIndexOf(')')
        if (open != -1 && close > open &&
            Regex("[A-Za-z_$][A-Za-z0-9_$.]*").matches(s.substring(0, open).trim()) &&
            s.substring(close + 1).trim() in setOf("", ";")) return s.substring(open + 1, close).trim()
        return s
    }

    fun parse(body: String): JsonValue = SrunJson.parse(strip(body))

    fun tryParse(body: String): JsonValue? = try {
        parse(body)
    } catch (e: Exception) {
        null
    }
}

object SrunResponseReader {

    fun errorOf(root: JsonValue.Obj): String? = root["error"]?.str()

    fun ecodeOf(root: JsonValue.Obj): String? =
        root["ecode"]?.str() ?: root["error_code"]?.str()

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

    fun isOk(root: JsonValue.Obj): Boolean = root["error"]?.str() == SrunProtocol.OK
}
