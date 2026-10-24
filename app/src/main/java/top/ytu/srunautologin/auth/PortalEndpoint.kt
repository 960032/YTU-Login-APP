package top.ytu.srunautologin.auth

import java.net.URI
import java.util.Locale

data class PortalConnectionSettings(val origin: String, val allowInsecureHttp: Boolean = false)

/** Canonical portal origin. Credentials, paths and query parameters are never configuration. */
object PortalEndpoint {
    private val label = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

    fun normalize(raw: String, defaultScheme: String = "https"): String? {
        val value = raw.trim()
        if (value.isEmpty() || value.any { it.isWhitespace() || it.isISOControl() }) return null
        val candidate = if ("://" in value) value else "$defaultScheme://$value"
        val uri = try { URI(candidate) } catch (_: Exception) { return null }
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        if (scheme != "https" && scheme != "http") return null
        if (uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) return null
        if (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/") return null
        val host = uri.host?.lowercase(Locale.ROOT) ?: return null
        val bareHost = host.removePrefix("[").removeSuffix("]")
        if ('%' in bareHost || bareHost.isEmpty()) return null
        if (':' !in bareHost) {
            if (bareHost.length > 253 || bareHost.split('.').any { !label.matches(it) }) return null
            if (bareHost.all { it.isDigit() || it == '.' }) {
                val octets = bareHost.split('.')
                if (octets.size != 4 || octets.any {
                    val number = it.toIntOrNull()
                    number == null || number !in 0..255 || (it.length > 1 && it.startsWith('0'))
                }) return null
            }
        }
        val port = uri.port
        if (port != -1 && port !in 1..65535) return null
        val authority = uri.rawAuthority ?: return null
        val suffix = if (authority.startsWith("[")) authority.substringAfter(']', "")
                     else authority.drop(host.length)
        if (suffix.isNotEmpty() && (port == -1 || suffix.first() != ':' || suffix.drop(1).toIntOrNull() != port)) return null
        val canonicalPort = when {
            scheme == "https" && port == 443 -> -1
            scheme == "http" && port == 80 -> -1
            else -> port
        }
        return try { URI(scheme, null, bareHost, canonicalPort, null, null, null).toASCIIString() }
        catch (_: Exception) { null }
    }

    fun originOf(url: String): String? = try {
        val uri = URI(url)
        if (uri.rawUserInfo != null) null
        else normalize(URI(uri.scheme, null, uri.host, uri.port, null, null, null).toString())
    } catch (_: Exception) { null }

    fun isCleartext(origin: String): Boolean = origin.startsWith("http://")
}
