package top.ytu.srunautologin.storage

import java.security.GeneralSecurityException
import java.security.ProviderException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

interface SecretKeyProvider {
    fun getOrCreate(): SecretKey
}

class FixedSecretKeyProvider(private val keyBytes: ByteArray) : SecretKeyProvider {
    init {
        require(keyBytes.size == 16 || keyBytes.size == 24 || keyBytes.size == 32) {
            "AES 密钥长度必须是 16/24/32 字节，实际 ${keyBytes.size}"
        }
    }

    override fun getOrCreate(): SecretKey = SecretKeySpec(keyBytes, "AES")
}

class SecureStoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

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

    fun encrypt(plain: ByteArray): ByteArray {
        val encrypted = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            // Let the provider generate a fresh IV. This works with both old keys that
            // forbid caller IVs and newer keys, without deleting or replacing either.
            cipher.init(Cipher.ENCRYPT_MODE, keyProvider.getOrCreate(), random)
            val iv = cipher.iv ?: throw GeneralSecurityException("加密提供者没有返回 IV")
            if (iv.size != IV_LENGTH) throw GeneralSecurityException("加密提供者返回了不支持的 IV 长度")
            iv to cipher.doFinal(plain)
        } catch (e: GeneralSecurityException) {
            throw SecureStoreException("加密失败：Keystore/算法不可用（${e.javaClass.simpleName}: ${e.message}）", e)
        } catch (e: ProviderException) {
            throw SecureStoreException("加密失败：Keystore 提供者异常（${e.javaClass.simpleName}: ${e.message}）", e)
        } catch (e: RuntimeException) {
            throw SecureStoreException("加密失败：运行时异常（${e.javaClass.simpleName}: ${e.message}）", e)
        }

        val (iv, cipherText) = encrypted
        val out = ByteArray(HEADER_LENGTH + IV_LENGTH + cipherText.size)
        out[0] = MAGIC
        out[1] = VERSION
        System.arraycopy(iv, 0, out, HEADER_LENGTH, IV_LENGTH)
        System.arraycopy(cipherText, 0, out, HEADER_LENGTH + IV_LENGTH, cipherText.size)
        return out
    }

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
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, keyProvider.getOrCreate(), GCMParameterSpec(TAG_BITS, iv))
            cipher.doFinal(cipherText)
        } catch (e: GeneralSecurityException) {
            throw SecureStoreException("GCM 认证失败：密文被篡改或密钥不匹配（${e.javaClass.simpleName}: ${e.message}）", e)
        } catch (e: ProviderException) {
            throw SecureStoreException("解密失败：Keystore 提供者异常（${e.javaClass.simpleName}: ${e.message}）", e)
        } catch (e: RuntimeException) {
            throw SecureStoreException("解密失败：运行时异常（${e.javaClass.simpleName}: ${e.message}）", e)
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
