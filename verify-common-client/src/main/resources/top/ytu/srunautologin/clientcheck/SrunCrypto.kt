package top.ytu.srunautologin.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SrunCrypto —— 深澜 SRun Portal 认证密码学原语的 Kotlin 移植（纯 JDK，零第三方依赖）。
 *
 * 判据基准（逐字符等价的唯一基准，只读）：
 *   artifacts/srun-impl/srun-crypto.js
 *   SHA256 = 1A56E0EA990F98E6D2A7E0F4A914FCBCEED86B7A52B0F6094EF076FEFD424FE6
 *
 * ============================ 移植总原则 ============================
 * JavaScript 的位运算一律先把操作数按 ToInt32 截成 **32 位有符号整数**，Kotlin 的 `Int` 位宽与语义与之完全一致：
 *
 *   JS `x >>> k`  ≡ Kotlin `x ushr k`   （逻辑右移，高位补 0，结果仍按 32 位有符号 Int 解释，位模式相同）
 *   JS `x << k`   ≡ Kotlin `x shl k`
 *   JS `x >> k`   ≡ Kotlin `x shr k`    （算术右移，补符号位）
 *   JS `x & y`    ≡ Kotlin `x and y`；`|` ≡ `or`；`^` ≡ `xor`
 *   JS 的位移量按 `k & 31` 取模，Kotlin 的 shl/shr/ushr 同样按 32 位掩码，二者一致。
 *
 * 【最大陷阱：`& 0xFFFFFFFF` 掩码】
 * 参考实现里的 `MASK = 0x8ce0d9bf | 0x731f2640 = 0xFFFFFFFF`，以及 `(d + c) & MASK`、`(v[p] + m) & MASK`
 * 这类写法，目的是把 JS 的 IEEE754 双精度加法结果截回 32 位（等价于 `>>> 0`）。
 * Kotlin 的 `Int` 加法**本身就是 32 位回绕**（溢出即丢弃高位，位模式与 ToInt32 完全相同），
 * 因此本实现直接写 `a + b`，**绝不重复写 `and 0xFFFFFFFF`**：写成 `(a + b) and 0xFFFFFFFF` 会得到 64 位/无符号
 * 语义（`and` 的右操作数会被当成 Long），反而偏离 JS。逐处见下方注释。
 * 同理 `(k[...] ^ z) >>> 0` 只是把结果规范化成无符号 32 位表示，位模式不变，随后参与 32 位回绕加法，故省略。
 *
 * ============================ 字符串口径 ============================
 * 参考实现用 `charCodeAt` 逐 **UTF-16 代码单元**处理；本实现一律用 `String[i].code`（≡ charCodeAt(i)）。
 * 绝不能改成 `getBytes(UTF_8)` + 标准 Base64 之类的「等价变换」，那会改变打包位序与填充语义。
 * 只有 `md5/sha1/hmacMd5` 走 UTF-8 字节流（与 Node 的 `Buffer.from(s, 'utf8')` 一致）。
 *
 * ============================ 公开 API（本任务内冻结） ============================
 * 与 Node 版导出的 7 个函数一一对应，**不得改名、不得改参数类型**：
 *   md5(s) / sha1(s) / hmacMd5(key, msg) / base64Encode(s) /
 *   passwordField(plainPwd, token) /
 *   chksum(token, username, hmd5, acId, ip, n, type, info) /
 *   infoField(username, plainPwd, ip, acId, token)
 *
 * 【调用方须知】`acId` 在本 API 中冻结为 `String`：Node 版 `infoField` 把它原样交给 `JSON.stringify`，
 * 传数字 5 会生成 `"acid":5`，传字符串 "5" 会生成 `"acid":"5"`。Kotlin 侧固定按字符串处理，
 * 因此调用方必须传字符串（与 srun-login.js 把 ac_id 当字符串使用的做法一致），否则 info 字段会不一致。
 */
object SrunCrypto {

    /** 自定义 base64 字母表（证据 all.min.js:16），硬编码常量，不读写任何全局 base64 状态。 */
    private const val CUSTOM_ALPHABET =
        "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

    private const val PAD_CHAR = '='

    /** info 字段的加密版本标记（证据 jquery.srun.portal.js:19）。 */
    const val ENC_VER: String = "srun_bx1"

    /** 参考实现 `_getbyte` 抛错文本，逐字保留。 */
    private const val ERR_INVALID_CHARACTER = "INVALID_CHARACTER_ERR: DOM Exception 5"

    private const val HEX_DIGITS = "0123456789abcdef"

    /* ======================= 基础摘要 ======================= */

    /** MD5，返回 hex 小写（Node: `createHash('md5').update(String(s),'utf8')`）。 */
    fun md5(s: String): String = digestHex("MD5", s)

    /** SHA1，返回 hex 小写。 */
    fun sha1(s: String): String = digestHex("SHA-1", s)

    private fun digestHex(algorithm: String, s: String): String =
        toHexLower(MessageDigest.getInstance(algorithm).digest(s.toByteArray(Charsets.UTF_8)))

    /**
     * HMAC-MD5，返回 hex 小写。
     *
     * 【空 key 退化分支必须保留】对齐 blueimp md5 v2.10.0 的双参形式 `md5(value, key)`：
     * 当 key 为空字符串时它不走 HMAC 分支，而是退化为普通 `md5(value)`。
     * 实测：`md5('', '') === md5('') === d41d8cd98f00b204e9800998ecf8427e`，
     * 而标准的 `createHmac('md5','')` 会得到 74e6f7298a9c2d168935f58c001bad88 —— 二者不同，故必须特判。
     */
    fun hmacMd5(key: String, msg: String): String {
        if (key.isEmpty()) return md5(msg)
        val mac = Mac.getInstance("HmacMD5")
        mac.init(SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacMD5"))
        return toHexLower(mac.doFinal(msg.toByteArray(Charsets.UTF_8)))
    }

    private fun toHexLower(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xFF
            out[i * 2] = HEX_DIGITS[b ushr 4]
            out[i * 2 + 1] = HEX_DIGITS[b and 0x0F]
        }
        return String(out)
    }

    /* ======================= 自定义 Base64 ======================= */

    /**
     * 用硬编码的自定义字母表做 Base64（位序、填充与 jquery-base64 v1.0 `_encode` 一致）。
     *
     * 位序（逐字对齐参考实现的 `_encode`）：
     *   b10 = (c0 << 16) | (c1 << 8) | c2
     *   x[0] = ALPHA[b10 >> 18]
     *   x[1] = ALPHA[(b10 >> 12) & 63]
     *   x[2] = ALPHA[(b10 >> 6) & 63]   （仅当本组实到字节数 > 1，否则 '='）
     *   x[3] = ALPHA[b10 & 63]          （仅当本组实到字节数 > 2，否则 '='）
     * 注意：`c0 <= 255` 保证 b10 只有低 24 位，因此 `b10 ushr 18` 天然落在 0..63，与 JS `b10 >> 18` 等价。
     *
     * 字符码 > 255 时抛错（对齐参考实现 `_getbyte` 的 `INVALID_CHARACTER_ERR: DOM Exception 5`）。
     * 输入按 UTF-16 代码单元处理（调用方传入的是 fromWords 产出的字节串，每单元 0x00-0xFF）。
     */
    fun base64Encode(s: String): String {
        val imax = s.length
        if (imax == 0) return ""
        val out = StringBuilder(((imax + 2) / 3) * 4)
        var i = 0
        while (i < imax) {
            val remainder = imax - i
            // 越界位置：参考实现 _getbyte 返回 NaN，NaN 参与 | 运算得 0，此处显式补 0，语义等价。
            val c0 = s[i].code
            val c1 = if (remainder > 1) s[i + 1].code else 0
            val c2 = if (remainder > 2) s[i + 2].code else 0
            if (c0 > 255 || c1 > 255 || c2 > 255) {
                throw IllegalArgumentException(ERR_INVALID_CHARACTER)
            }
            // Int 位运算 = 32 位有符号，与 JS 一致；(c0<<16)|(c1<<8)|c2 只占低 24 位，符号位为 0。
            val b10 = (c0 shl 16) or (c1 shl 8) or c2
            out.append(CUSTOM_ALPHABET[b10 ushr 18])
            out.append(CUSTOM_ALPHABET[(b10 ushr 12) and 63])
            out.append(if (remainder > 1) CUSTOM_ALPHABET[(b10 ushr 6) and 63] else PAD_CHAR)
            out.append(if (remainder > 2) CUSTOM_ALPHABET[b10 and 63] else PAD_CHAR)
            i += 3
        }
        return out.toString()
    }

    /* ======================= TEA 变体 xEncode ======================= */

    /**
     * 字符串 -> 32bit 小端字数组（参考实现 toWords）。
     * withLength=true 时在末尾追加「原始字符长度」。越界位置显式补 0（对齐 `NaN << 8 === 0`）。
     */
    private fun toWords(a: String, withLength: Boolean): IntArray {
        val c = a.length
        val words = ArrayList<Int>(c / 4 + 2)
        var i = 0
        while (i < c) {
            val c1 = if (i + 1 < c) a[i + 1].code else 0
            val c2 = if (i + 2 < c) a[i + 2].code else 0
            val c3 = if (i + 3 < c) a[i + 3].code else 0
            // 逐字对应 `a.charCodeAt(i) | (c1 << 8) | (c2 << 16) | (c3 << 24)`：
            // c3 << 24 可能置位符号位，Kotlin Int 的 shl 同样是 32 位有符号语义，位模式与 JS 相同。
            words.add(a[i].code or (c1 shl 8) or (c2 shl 16) or (c3 shl 24))
            i += 4
        }
        if (withLength) words.add(c)
        return words.toIntArray()
    }

    /** 32bit 字数组 -> 字节串（每字拆成 4 个小端字节，参考实现 fromWords 的 b=false 分支）。 */
    private fun fromWords(a: IntArray): String {
        val sb = StringBuilder(a.size * 4)
        for (word in a) {
            sb.append((word and 0xFF).toChar())
            sb.append(((word ushr 8) and 0xFF).toChar())
            sb.append(((word ushr 16) and 0xFF).toChar())
            sb.append(((word ushr 24) and 0xFF).toChar())
        }
        return sb.toString()
    }

    /**
     * xEncode —— TEA 变体，逐行对照参考实现移植。要点：
     *  - delta = 0x86014019 | 0x183639a0 = 0x9E3779B9
     *  - 累加掩码 0x8ce0d9bf | 0x731f2640 = 0xFFFFFFFF（32 位回绕；Kotlin Int 加法天然等价，见文件头说明）
     *  - 轮数 q = floor(6 + 52 / (n + 1))，其中 n = v.length - 1 —— 这个 n 是**局部变量**，
     *    遮蔽了模块级 n = 200（参考实现的真实行为，必须照抄；本类不定义模块级 n，故无遮蔽问题）
     *  - key 不足 4 个 32bit 字时补齐；JS 补的是 undefined，参与 `^` 时视为 0，本实现用 keyAt() 返回 0
     *  - str 为空串时返回 ""
     */
    internal fun xEncode(str: String, key: String): String {
        if (str.isEmpty()) return ""

        val v = toWords(str, true)
        val k = toWords(key, false)
        // JS: `if (k.length < 4) k.length = 4;` 之后 `k[(p & 3) ^ e]` 的索引恒在 0..3。
        // key 少于 4 个字时索引越界 -> JS 取到 undefined -> ToInt32(undefined)=0；这里显式返回 0。
        // key 多于 4 个字时 JS 不会截断（只有 `length < 4` 才赋值），故这里也不截断，保留完整数组。
        fun keyAt(index: Int): Int = if (index < k.size) k[index] else 0

        val n = v.size - 1
        var z = v[n]
        var y = v[0]
        // delta：JS 写作 `0x86014019 | 0x183639a0`。
        // 【位宽陷阱】0x86014019 > Int.MAX_VALUE，在 Kotlin 里该字面量会被推断为 **Long**，
        // 若直接参与位运算会得到 Long 结果（编译期即报 assignment type mismatch）。
        // 必须先 .toInt() 截成 32 位有符号（= -2046734823），再与 0x183639A0 做 Int 位或，
        // 结果 0x9E3779B9 作为有符号 Int 即 -1640531527，与 JS 的 ToInt32 结果位模式完全一致。
        val c: Int = 0x86014019.toInt() or 0x183639A0
        var q = 6 + 52 / (n + 1)                  // Math.floor(6 + 52/(n+1))，正数下整除等价
        var d = 0
        var p: Int

        while (q > 0) {                            // 等价于 JS `while (0 < q--)`
            q -= 1
            // JS `d = (d + c) & MASK`；Kotlin Int 加法即 32 位回绕，掩码 0xFFFFFFFF 是恒等操作，故不再掩码。
            d += c
            val e = (d ushr 2) and 3
            p = 0
            while (p < n) {
                y = v[p + 1]
                var m = (z ushr 5) xor (y shl 2)                    // JS: (z>>>5)^(y<<2)
                m += ((y ushr 3) xor (z shl 4)) xor (d xor y)       // JS: += ((y>>>3)^(z<<4))^(d^y)
                m += (keyAt((p and 3) xor e) xor z)                 // JS: += (k[...]^z)>>>0（位模式不变，省略）
                z = v[p] + m                                        // JS: z = v[p] = (v[p]+m) & MASK
                v[p] = z
                p += 1
            }
            // 退出内层循环时 p == n，与 JS 相同，因此下面 (p & 3) 用的就是 n。
            y = v[0]
            var m = (z ushr 5) xor (y shl 2)
            m += ((y ushr 3) xor (z shl 4)) xor (d xor y)
            m += (keyAt((p and 3) xor e) xor z)
            z = v[n] + m
            v[n] = z
        }

        return fromWords(v)
    }

    /* ======================= 组装函数 ======================= */

    /** password 参数：`"{MD5}" + HMAC-MD5(token, 明文密码)`。 */
    fun passwordField(plainPwd: String, token: String): String = "{MD5}" + hmacMd5(token, plainPwd)

    /**
     * chksum 参数（SHA1 hex 小写）：token 既是首字段也是 7 个字段之间的分隔符，
     * 字段顺序固定为 username, hmd5, ac_id, ip, n, type, info。
     * `n`/`type` 为 Int，Kotlin `toString()` 与 JS 数字转字符串的十进制表示一致。
     */
    fun chksum(
        token: String,
        username: String,
        hmd5: String,
        acId: String,
        ip: String,
        n: Int,
        type: Int,
        info: String,
    ): String {
        var chkstr = token + username
        chkstr += token + hmd5
        chkstr += token + acId
        chkstr += token + ip
        chkstr += token + n
        chkstr += token + type
        chkstr += token + info
        return sha1(chkstr)
    }

    /**
     * info 参数：`"{SRBX1}" + base64Encode(xEncode(JSON.stringify({username,password,ip,acid,enc_ver}), token))`。
     * 字段顺序必须与参考实现一致（username, password, ip, acid, enc_ver），且不得含任何多余空白。
     */
    fun infoField(username: String, plainPwd: String, ip: String, acId: String, token: String): String {
        val plain = "{" +
            "\"username\":" + jsonString(username) + "," +
            "\"password\":" + jsonString(plainPwd) + "," +
            "\"ip\":" + jsonString(ip) + "," +
            "\"acid\":" + jsonString(acId) + "," +
            "\"enc_ver\":" + jsonString(ENC_VER) +
            "}"
        return "{SRBX1}" + base64Encode(xEncode(plain, token))
    }

    /**
     * 逐字对齐 `JSON.stringify(string)` 的字符串字面量（无缩进形式）：
     * `"` 与 `\` 转义；0x08/0x09/0x0A/0x0C/0x0D 用短转义；其余 < 0x20 用 `\u00xx`（小写 hex）；
     * 未配对的代理码元按 ES2019 well-formed JSON.stringify 转成 `\uXXXX`；其余字符原样输出（含非 ASCII）。
     */
    private fun jsonString(s: String): String {
        val sb = StringBuilder(s.length + 2)
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val ch = s[i]
            when {
                ch == '"' -> sb.append("\\\"")
                ch == '\\' -> sb.append("\\\\")
                ch == '\u0008' -> sb.append("\\b")
                ch == '\u0009' -> sb.append("\\t")
                ch == '\u000A' -> sb.append("\\n")
                ch == '\u000C' -> sb.append("\\f")
                ch == '\u000D' -> sb.append("\\r")
                ch < ' ' -> appendUnicodeEscape(sb, ch.code)
                ch.isHighSurrogate() -> {
                    if (i + 1 < s.length && s[i + 1].isLowSurrogate()) {
                        sb.append(ch).append(s[i + 1])   // 合法代理对：原样输出（JSON.stringify 亦然）
                        i += 1
                    } else {
                        appendUnicodeEscape(sb, ch.code) // 未配对高代理
                    }
                }
                ch.isLowSurrogate() -> appendUnicodeEscape(sb, ch.code) // 未配对低代理
                else -> sb.append(ch)
            }
            i += 1
        }
        sb.append('"')
        return sb.toString()
    }

    /** 追加 `\uXXXX`（小写 hex），不依赖 Locale/格式化 API。 */
    private fun appendUnicodeEscape(sb: StringBuilder, code: Int) {
        sb.append("\\u")
        sb.append(HEX_DIGITS[(code ushr 12) and 0x0F])
        sb.append(HEX_DIGITS[(code ushr 8) and 0x0F])
        sb.append(HEX_DIGITS[(code ushr 4) and 0x0F])
        sb.append(HEX_DIGITS[code and 0x0F])
    }
}
