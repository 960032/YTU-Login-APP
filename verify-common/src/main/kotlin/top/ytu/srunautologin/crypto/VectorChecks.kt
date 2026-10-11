package top.ytu.srunautologin.crypto

import java.io.File

/**
 * 向量核对引擎（零第三方依赖，只用 Kotlin 标准库 + java.io）。
 *
 * 同一份逻辑被两处复用：
 *   1) app/src/test/java/.../SrunCryptoTest.kt —— Android 单元测试（JUnit 4）。srcDir 指向本目录。
 *   2) jvm-check/src/main/kotlin/.../VectorCheck.kt —— 纯 JVM 运行器（本机无 Android SDK 时的实际执行路径）。
 *
 * 判据来源：testvectors/vectors.json（**全部由 Node 版 srun-crypto.js 现算产出**，只用合成数据）。
 * 核对方式：Kotlin 实现输出与期望值做**逐字符相等**比较；不一致时 detail 必须带出「输入 / 期望 / 实际」。
 */
object VectorChecks {

    /** 单条用例结果。 */
    data class Case(
        val category: String,
        val index: Int,
        val label: String,
        val ok: Boolean,
        val detail: String,
    )

    /** 整体结果。 */
    class Result(val cases: List<Case>) {
        val total: Int get() = cases.size
        val passed: Int get() = cases.count { it.ok }
        val failures: List<Case> get() = cases.filter { !it.ok }

        /** 分类汇总：类别 -> (通过数, 总数)。 */
        fun perCategory(): List<Triple<String, Int, Int>> =
            cases.groupBy { it.category }.map { (cat, list) -> Triple(cat, list.count { it.ok }, list.size) }
    }

    fun run(vectorsFile: File): Result {
        require(vectorsFile.isFile) { "向量文件不存在: ${vectorsFile.absolutePath}" }
        val text = vectorsFile.readText(Charsets.UTF_8)
        val root = MiniJson.parse(text) as? Map<*, *>
            ?: throw IllegalStateException("向量文件根节点不是 JSON 对象: ${vectorsFile.absolutePath}")

        val cases = ArrayList<Case>()

        /** 逐字符比对；不一致时 detail 带出输入 / 期望 / 实际。 */
        fun check(category: String, index: Int, label: String, expected: String, actual: String) {
            val ok = expected == actual
            cases.add(
                Case(
                    category, index, label, ok,
                    if (ok) "ok"
                    else "输入=${label} 期望=${esc(expected)} 实际=${esc(actual)}" +
                        "（期望长度=${expected.length}，实际长度=${actual.length}）"
                )
            )
        }

        val md5List = root["md5"] as List<*>
        md5List.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val input = str(m["input"])
            check("md5", i, esc(input), str(m["expected"]), SrunCrypto.md5(input))
        }

        val sha1List = root["sha1"] as List<*>
        sha1List.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val input = str(m["input"])
            check("sha1", i, esc(input), str(m["expected"]), SrunCrypto.sha1(input))
        }

        val hmacList = root["hmacMd5"] as List<*>
        hmacList.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val key = str(m["key"])
            val msg = str(m["msg"])
            val label = "key=${esc(key)} msg=${esc(msg)}"
            check("hmacMd5", i, label, str(m["expected"]), SrunCrypto.hmacMd5(key, msg))
        }

        val b64List = root["base64Encode"] as List<*>
        b64List.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val input = str(m["input"])
            val label = esc(input)
            if (m["expectError"] == true) {
                // 边界：字符码 > 255 必须抛错（对齐参考实现 _getbyte）
                val thrown: Throwable? = try {
                    SrunCrypto.base64Encode(input)
                    null
                } catch (t: Throwable) {
                    t
                }
                val ok = thrown != null && (thrown.message ?: "").contains("INVALID_CHARACTER_ERR")
                cases.add(
                    Case(
                        "base64Encode", i, "expectError " + label, ok,
                        if (ok) "ok（抛出 ${thrown!!.javaClass.name}: ${thrown.message}）"
                        else "输入=${label} 期望=抛错(INVALID_CHARACTER_ERR) 实际=" +
                            (thrown?.toString() ?: "未抛错（调用正常返回），返回值=${esc(runCatching { SrunCrypto.base64Encode(input) }.getOrDefault(""))}")
                    )
                )
            } else {
                check("base64Encode", i, label, str(m["expected"]), SrunCrypto.base64Encode(input))
            }
        }

        val pwdList = root["passwordField"] as List<*>
        pwdList.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val pwd = str(m["plainPwd"])
            val token = str(m["token"])
            val label = "plainPwd=${esc(pwd)} token=${esc(token)}"
            check("passwordField", i, label, str(m["expected"]), SrunCrypto.passwordField(pwd, token))
        }

        val chkList = root["chksum"] as List<*>
        chkList.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val token = str(m["token"])
            val username = str(m["username"])
            val hmd5 = str(m["hmd5"])
            val acId = str(m["acId"])
            val ip = str(m["ip"])
            val n = num(m["n"])
            val type = num(m["type"])
            val info = str(m["info"])
            val label = "token=${esc(token)} username=${esc(username)} acId=$acId ip=$ip n=$n type=$type"
            check(
                "chksum", i, label, str(m["expected"]),
                SrunCrypto.chksum(token, username, hmd5, acId, ip, n, type, info)
            )
        }

        val infoList = root["infoField"] as List<*>
        infoList.forEachIndexed { i, e ->
            val m = e as Map<*, *>
            val username = str(m["username"])
            val pwd = str(m["plainPwd"])
            val ip = str(m["ip"])
            val acId = str(m["acId"])
            val token = str(m["token"])
            val label = "username=${esc(username)} ip=$ip acId=$acId token=${esc(token)}"
            check(
                "infoField", i, label, str(m["expected"]),
                SrunCrypto.infoField(username, pwd, ip, acId, token)
            )
        }

        return Result(cases)
    }

    private fun str(v: Any?): String = v as? String ?: throw IllegalStateException("向量字段缺失或不是字符串: $v")

    private fun num(v: Any?): Int = (v as? Number)?.toInt() ?: throw IllegalStateException("向量字段缺失或不是数字: $v")

    /** 把不可见字符转义并截断，仅用于打印，不参与比较。 */
    private fun esc(s: String, max: Int = 96): String {
        val sb = StringBuilder()
        for (ch in s) {
            when {
                ch == '\u0000' -> sb.append("\\0")
                ch == '\n' -> sb.append("\\n")
                ch == '\r' -> sb.append("\\r")
                ch == '\t' -> sb.append("\\t")
                ch.code < 0x20 -> sb.append("\\u").append(String.format("%04x", ch.code))
                ch.code in 0x7F..0x9F -> sb.append("\\u").append(String.format("%04x", ch.code))
                else -> sb.append(ch)
            }
            if (sb.length >= max) {
                sb.append("…(共").append(s.length).append("字符)")
                return sb.toString()
            }
        }
        return sb.toString()
    }
}

/**
 * 极简 JSON 解析器（仅覆盖 vectors.json 用到的语法：object/array/string/number/true/false/null）。
 * 不用第三方库是本任务的硬约束，因此自带一个只读解析器。
 * 支持 `\uXXXX` 转义（可组成代理对）与常见短转义；数字统一解析为 Double。
 */
internal object MiniJson {

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.value()
        p.skipWs()
        require(p.eof()) { "JSON 解析：末尾存在多余内容（offset=${p.pos}）" }
        return v
    }

    private class Parser(private val s: String) {
        var pos = 0

        fun eof(): Boolean = pos >= s.length

        fun skipWs() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        fun value(): Any? {
            skipWs()
            require(!eof()) { "JSON 解析：意外结束（offset=$pos）" }
            return when (s[pos]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> string()
                't' -> { literal("true"); true }
                'f' -> { literal("false"); false }
                'n' -> { literal("null"); null }
                else -> number()
            }
        }

        private fun obj(): Map<String, Any?> {
            expect('{')
            val m = LinkedHashMap<String, Any?>()
            skipWs()
            if (peek() == '}') { pos++; return m }
            while (true) {
                skipWs()
                val k = string()
                skipWs()
                expect(':')
                m[k] = value()
                skipWs()
                when (val c = peek()) {
                    ',' -> pos++
                    '}' -> { pos++; return m }
                    else -> throw IllegalArgumentException("JSON 解析：对象内期望 , 或 } 但遇到 '$c'（offset=$pos）")
                }
            }
        }

        private fun arr(): List<Any?> {
            expect('[')
            val list = ArrayList<Any?>()
            skipWs()
            if (peek() == ']') { pos++; return list }
            while (true) {
                list.add(value())
                skipWs()
                when (val c = peek()) {
                    ',' -> pos++
                    ']' -> { pos++; return list }
                    else -> throw IllegalArgumentException("JSON 解析：数组内期望 , 或 ] 但遇到 '$c'（offset=$pos）")
                }
            }
        }

        private fun string(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                require(!eof()) { "JSON 解析：字符串未闭合（offset=$pos）" }
                val c = s[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        require(!eof()) { "JSON 解析：转义符后意外结束（offset=$pos）" }
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                require(pos + 4 <= s.length) { "JSON 解析：\\u 转义不完整（offset=$pos）" }
                                sb.append(Integer.parseInt(s.substring(pos, pos + 4), 16).toChar())
                                pos += 4
                            }
                            else -> throw IllegalArgumentException("JSON 解析：未知转义 \\$e（offset=$pos）")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun number(): Double {
            val start = pos
            if (!eof() && (s[pos] == '-' || s[pos] == '+')) pos++
            while (!eof() && (s[pos].isDigit() || s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E' ||
                        ((s[pos] == '-' || s[pos] == '+') && (s[pos - 1] == 'e' || s[pos - 1] == 'E')))
            ) pos++
            require(pos > start) { "JSON 解析：不是合法数字（offset=$start）" }
            return s.substring(start, pos).toDouble()
        }

        private fun literal(word: String) {
            require(s.startsWith(word, pos)) { "JSON 解析：期望字面量 $word（offset=$pos）" }
            pos += word.length
        }

        private fun peek(): Char {
            require(!eof()) { "JSON 解析：意外结束（offset=$pos）" }
            return s[pos]
        }

        private fun expect(c: Char) {
            require(!eof() && s[pos] == c) { "JSON 解析：期望 '$c' 但遇到 ${if (eof()) "EOF" else "'${s[pos]}'"}（offset=$pos）" }
            pos++
        }
    }
}
