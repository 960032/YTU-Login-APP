package top.ytu.srunautologin.storage

import java.security.GeneralSecurityException
import java.security.ProviderException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * KEK（密钥加密密钥）的可注入接口。
 *
 * 真机实现：[top.ytu.srunautologin.platform.AndroidKeystoreSecretKeyProvider]（Android Keystore，硬件保护）；
 * JVM 测试实现：[FixedSecretKeyProvider]。把密钥来源挡在接口后面，
 * 加解密往返逻辑才能在纯 JVM 单元测试里验证，无需真机、无需 Android SDK。
 */
interface SecretKeyProvider {
    fun getOrCreate(): SecretKey
}

/** 固定密钥提供者：**仅供测试**，真机不使用（真机走 Android Keystore）。 */
class FixedSecretKeyProvider(private val keyBytes: ByteArray) : SecretKeyProvider {
    init {
        require(keyBytes.size == 16 || keyBytes.size == 24 || keyBytes.size == 32) {
            "AES 密钥长度必须是 16/24/32 字节，实际 ${keyBytes.size}"
        }
    }

    override fun getOrCreate(): SecretKey = SecretKeySpec(keyBytes, "AES")
}

/** 加解密失败（密文被篡改、密钥不匹配、格式非法）统一抛出本异常。 */
class SecureStoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * 基于 AES/GCM 的加解密（KEK 由 [SecretKeyProvider] 提供）。
 *
 * 落盘格式（自定义，二进制）：`'S'(0x53) | 版本(0x01) | IV(12 字节) | 密文+GCM 认证标签(16 字节)`
 * 落盘时整体再做 Base64（见 [encryptToBase64String]）。**任何明文都不落盘。**
 *
 * 本文件只用 JDK 的 java.security / javax.crypto / java.util.Base64（Android API 26+ 均有），
 * 因此是纯 JVM 代码，可离线编译与测试。
 */
class SecureStore(private val keyProvider: SecretKeyProvider) {

    companion object {
        const val MAGIC: Byte = 0x53          // 'S'
        const val VERSION: Byte = 0x01
        const val IV_LENGTH = 12              // GCM 推荐 96 bit IV
        const val TAG_BITS = 128
        const val HEADER_LENGTH = 2
        const val TAG_LENGTH = 16
        const val TRANSFORMATION = "AES/GCM/NoPadding"

        fun bytesToBase64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
        fun base64ToBytes(text: String): ByteArray = Base64.getDecoder().decode(text)
    }

    private val random = SecureRandom()

    /**
     * 加密：每次调用都生成**新的随机 IV**（SecureRandom），因此同一明文两次加密的密文必然不同。
     * 失败一律收敛为 [SecureStoreException]（保留 cause），与 decrypt() 口径一致——底层可能是
     * GeneralSecurityException，也可能是 Keystore 抛出的 ProviderException。
     */
    fun encrypt(plain: ByteArray): ByteArray {
        val iv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }   // 每次全新随机 IV，绝不复用（GCM 前提）
        val cipherText = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, keyProvider.getOrCreate(), GCMParameterSpec(TAG_BITS, iv))
            cipher.doFinal(plain)
        } catch (e: GeneralSecurityException) {
            // 与 decrypt() 同口径：收敛成 SecureStoreException 并保留 cause，调用方才有机会显示可见错误。
            throw SecureStoreException("加密失败：Keystore/算法不可用（${e.javaClass.simpleName}: ${e.message}）", e)
        } catch (e: ProviderException) {
            // Keystore 也可能抛 ProviderException（RuntimeException 子类，不是 GeneralSecurityException 子类）：
            // 例如硬件密钥不可用、密钥被系统失效。同样收敛并保留 cause。
            throw SecureStoreException("加密失败：Keystore 提供者异常（${e.javaClass.simpleName}: ${e.message}）", e)
        }

        val out = ByteArray(HEADER_LENGTH + IV_LENGTH + cipherText.size)
        out[0] = MAGIC
        out[1] = VERSION
        System.arraycopy(iv, 0, out, HEADER_LENGTH, IV_LENGTH)
        System.arraycopy(cipherText, 0, out, HEADER_LENGTH + IV_LENGTH, cipherText.size)
        return out
    }

    /** 解密：GCM 认证失败（密文/IV/标签被篡改）时抛出 [SecureStoreException]。 */
    fun decrypt(payload: ByteArray): ByteArray {
        if (payload.size < HEADER_LENGTH + IV_LENGTH + TAG_LENGTH) {
            throw SecureStoreException(
                "密文长度不足：${payload.size} < ${HEADER_LENGTH + IV_LENGTH + TAG_LENGTH}"
            )
        }
        if (payload[0] != MAGIC || payload[1] != VERSION) {
            throw SecureStoreException("密文头校验失败（magic/版本不匹配）")
        }
        val iv = payload.copyOfRange(HEADER_LENGTH, HEADER_LENGTH + IV_LENGTH)
        val cipherText = payload.copyOfRange(HEADER_LENGTH + IV_LENGTH, payload.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        return try {
            cipher.init(Cipher.DECRYPT_MODE, keyProvider.getOrCreate(), GCMParameterSpec(TAG_BITS, iv))
            cipher.doFinal(cipherText)
        } catch (e: GeneralSecurityException) {
            throw SecureStoreException("GCM 认证失败：密文被篡改或密钥不匹配", e)
        }
    }

    fun encryptToBase64String(plain: String): String =
        bytesToBase64(encrypt(plain.toByteArray(Charsets.UTF_8)))

    fun decryptFromBase64String(text: String): String {
        val bytes = try {
            base64ToBytes(text)
        } catch (e: IllegalArgumentException) {
            throw SecureStoreException("Base64 解码失败", e)
        }
        return String(decrypt(bytes), Charsets.UTF_8)
    }
}