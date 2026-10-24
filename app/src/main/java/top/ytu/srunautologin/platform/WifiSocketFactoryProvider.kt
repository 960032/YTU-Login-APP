package top.ytu.srunautologin.platform

import android.content.Context
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import top.ytu.srunautologin.auth.RequestDeadline
import top.ytu.srunautologin.auth.SocketFactoryProvider

/** DNS and TCP both use the captured network; the returned socket is connected. */
class WifiSocketFactoryProvider(private val binding: WifiFirstConnectionFactory) : SocketFactoryProvider {
    constructor(context: Context) : this(WifiFirstConnectionFactory(context))

    override fun createSocket(host: String, port: Int, timeoutMs: Int): Socket {
        val deadline = RequestDeadline(timeoutMs)
        val network = binding.requireNetwork()
        val lookup = try { resolver.submit(java.util.concurrent.Callable { network.getAllByName(host) }) }
        catch (_: java.util.concurrent.RejectedExecutionException) { throw IOException("DNS 查询繁忙") }
        val addresses = try { lookup.get(deadline.remainingMs().toLong(), java.util.concurrent.TimeUnit.MILLISECONDS) }
        catch (_: java.util.concurrent.TimeoutException) { throw java.net.SocketTimeoutException("DNS 查询超时") }
        catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw java.io.InterruptedIOException("认证已取消")
        } catch (_: java.util.concurrent.ExecutionException) { throw IOException("目标 WiFi DNS 查询失败") }
        finally { lookup.cancel(true) }
        var failure: IOException? = null
        for (address in addresses) {
            binding.requireNetwork()
            val socket = network.socketFactory.createSocket()
            binding.trackSocket(socket)
            try {
                socket.soTimeout = deadline.remainingMs()
                socket.connect(InetSocketAddress(address, port), deadline.remainingMs())
                binding.requireNetwork()
                return socket
            } catch (e: IOException) {
                failure = e
                socket.close()
            } catch (e: Exception) {
                socket.close()
                throw e
            }
        }
        throw failure ?: IOException("无法在目标 WiFi 上解析门户地址")
    }
    companion object {
        // A stuck platform DNS call cannot create an unbounded number of threads.
        private val resolver = java.util.concurrent.ThreadPoolExecutor(0, 2, 30,
            java.util.concurrent.TimeUnit.SECONDS, java.util.concurrent.SynchronousQueue<Runnable>(),
            java.util.concurrent.ThreadFactory { runnable -> Thread(runnable, "srun-wifi-dns").apply { isDaemon = true } })
    }
}
