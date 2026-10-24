package top.ytu.srunautologin.auth

import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit

/** A read timeout alone is not an overall request deadline. */
class RequestDeadline(timeoutMs: Int) {
    private val endsAt = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs.coerceIn(1, 120_000).toLong())

    fun remainingMs(): Int {
        if (Thread.currentThread().isInterrupted) throw InterruptedIOException("认证任务已取消")
        val remaining = endsAt - System.nanoTime()
        if (remaining <= 0L) throw SocketTimeoutException("认证请求已超过总时限")
        return TimeUnit.NANOSECONDS.toMillis(remaining).coerceAtLeast(1L).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }
}

class ResponseTooLargeException : IOException("门户响应超过允许大小")
class NetworkBindingException(message: String = "目标 WiFi 不可用，已停止请求") : IOException(message)
class UnsafeRedirectException : IOException("门户重定向被拒绝，请填写最终的认证门户地址")
