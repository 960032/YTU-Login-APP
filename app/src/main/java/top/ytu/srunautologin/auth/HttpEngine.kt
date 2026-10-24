package top.ytu.srunautologin.auth

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL

interface HttpEngine {
    @Throws(IOException::class)
    fun get(url: String, timeoutMs: Int): AuthResponse
}

interface LocalIpProbe {
    fun probe(host: String, port: Int, timeoutMs: Int): String?
}

/** Injected factories are mandatory bindings: failure must not choose another network. */
interface ConnectionFactory {
    @Throws(IOException::class)
    fun open(url: URL): java.net.URLConnection?
}

class HttpUrlConnectionEngine(
    private val connectTimeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    private val readTimeoutMs: Int = SrunProtocol.DEFAULT_TIMEOUT_MS,
    private val connectionFactory: ConnectionFactory? = null,
    private val retryCount: Int = DEFAULT_RETRY_COUNT,
    private val retryDelayMs: Long = DEFAULT_RETRY_DELAY_MS,
    private val attemptTimeoutCapMs: Int = DEFAULT_ATTEMPT_TIMEOUT_MS,
    private val log: (String) -> Unit = {},
    private val maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES
) : HttpEngine {
    init {
        require(maxResponseBytes in 1..MAX_RESPONSE_BYTES)
        require(retryCount in 0..5)
        require(retryDelayMs in 0..10_000)
        require(connectTimeoutMs > 0 && readTimeoutMs > 0 && attemptTimeoutCapMs > 0)
    }

    override fun get(url: String, timeoutMs: Int): AuthResponse {
        val target = URL(url)
        if (PortalEndpoint.originOf(url) == null || target.ref != null) {
            throw IOException("门户请求地址无效")
        }
        val deadline = RequestDeadline(if (timeoutMs > 0) timeoutMs else connectTimeoutMs)
        // An interrupted login may already have reached the server. Re-probe on the next
        // authentication run instead of replaying a credential-bearing request here.
        val attempts = if (target.path == SrunProtocol.PATH_PORTAL) 1 else retryCount + 1
        var lastError: IOException? = null
        for (attempt in 1..attempts) {
            try {
                return attemptGet(target, deadline)
            } catch (e: IOException) {
                if (e is NetworkBindingException || e is ResponseTooLargeException ||
                    e is UnsafeRedirectException || e is javax.net.ssl.SSLException ||
                    (e is InterruptedIOException && Thread.currentThread().isInterrupted)) throw e
                lastError = e
                // Never log a URL query or exception text: either may contain credentials.
                log("HTTP 请求失败 attempt=$attempt/$attempts host=${target.host}" +
                    " network=${if (connectionFactory == null) "direct" else "pinned-wifi"}" +
                    " exception=${e.javaClass.simpleName}")
                if (attempt < attempts) {
                    val delay = minOf(retryDelayMs, deadline.remainingMs().toLong())
                    try { Thread.sleep(delay) }
                    catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw InterruptedIOException("认证任务已取消")
                    }
                }
            }
        }
        throw lastError ?: IOException("门户请求失败")
    }

    private fun attemptGet(target: URL, deadline: RequestDeadline): AuthResponse {
        val opened = if (connectionFactory == null) target.openConnection(Proxy.NO_PROXY)
        else try { connectionFactory.open(target) ?: throw NetworkBindingException() }
        catch (e: IOException) { throw e }
        catch (_: Exception) { throw NetworkBindingException() }
        val connection = opened as? HttpURLConnection
            ?: throw IOException("门户仅支持 HTTP 或 HTTPS")
        try {
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = minOf(connectTimeoutMs, attemptTimeoutCapMs, deadline.remainingMs())
            connection.readTimeout = minOf(readTimeoutMs, deadline.remainingMs())
            connection.setRequestProperty("Accept", "application/json, application/javascript, text/plain, text/html")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("Cache-Control", "no-store")
            connection.setRequestProperty("Pragma", "no-cache")
            connection.setRequestProperty("User-Agent", "SrunAutoLogin-Android/0.2")
            val status = connection.responseCode
            deadline.remainingMs()
            if (status in 300..399) throw UnsafeRedirectException()
            if (connection.contentLengthLong > maxResponseBytes) throw ResponseTooLargeException()
            val input = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = input?.use { readBounded(it, connection, deadline) }.orEmpty()
            return AuthResponse(status, body)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: InputStream, connection: HttpURLConnection, deadline: RequestDeadline): String {
        val output = ByteArrayOutputStream(minOf(maxResponseBytes, 8192))
        val buffer = ByteArray(8192)
        while (true) {
            connection.readTimeout = minOf(readTimeoutMs, deadline.remainingMs())
            val size = input.read(buffer, 0, minOf(buffer.size, maxResponseBytes - output.size() + 1))
            if (size < 0) break
            if (size == 0) continue
            if (output.size() + size > maxResponseBytes) throw ResponseTooLargeException()
            output.write(buffer, 0, size)
        }
        deadline.remainingMs()
        return output.toByteArray().toString(Charsets.UTF_8)
    }

    companion object {
        const val DEFAULT_RETRY_COUNT = 2
        const val DEFAULT_RETRY_DELAY_MS = 500L
        const val DEFAULT_ATTEMPT_TIMEOUT_MS = 7_000
        const val DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
        const val MAX_RESPONSE_BYTES = 1024 * 1024
    }
}

/** Returns an already connected socket on the same network as HTTP. */
interface SocketFactoryProvider {
    @Throws(IOException::class)
    fun createSocket(host: String, port: Int, timeoutMs: Int): Socket?
}

class SocketLocalIpProbe(private val socketFactory: SocketFactoryProvider? = null) : LocalIpProbe {
    override fun probe(host: String, port: Int, timeoutMs: Int): String? {
        val timeout = if (timeoutMs > 0) timeoutMs else SrunProtocol.DEFAULT_TIMEOUT_MS
        return try {
            val socket = if (socketFactory != null) socketFactory.createSocket(host, port, timeout)
            else Socket().apply {
                try { connect(InetSocketAddress(host, port), timeout) }
                catch (e: Exception) { close(); throw e }
            }
            socket?.use { if (it.isConnected) it.localAddress?.hostAddress else null }
        } catch (_: IOException) { null }
        catch (_: SecurityException) { null }
    }
}
