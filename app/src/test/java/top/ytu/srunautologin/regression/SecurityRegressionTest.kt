package top.ytu.srunautologin.regression

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import top.ytu.srunautologin.auth.*
import top.ytu.srunautologin.flow.*
import top.ytu.srunautologin.log.*
import top.ytu.srunautologin.net.*
import top.ytu.srunautologin.storage.*
import top.ytu.srunautologin.work.*

class SecurityRegressionTest {
    private fun store() = SecureStore(FixedSecretKeyProvider(ByteArray(32) { it.toByte() }))
    private fun fail(block: () -> Unit) {
        try { block() } catch (_: Exception) { return }
        throw AssertionError("Expected rejected operation")
    }
    private fun done(code: String, failure: AuthFailure = AuthFailure.PORTAL_UNREACHABLE) =
        AuthFlowOutcome.Done(AuthResult.failure(failure, code, "synthetic", "login", 1), "campus", "campus", "account")

    @Test fun endpointPreservesSchemePortAndRejectsCredentialInjection() {
        assertEquals("https://portal.example:8443", PortalEndpoint.normalize("https://PORTAL.example:8443/"))
        assertEquals("https://portal.example", PortalEndpoint.normalize("portal.example"))
        assertEquals("http://10.0.0.1", PortalEndpoint.normalize("http://10.0.0.1:80"))
        assertEquals("https://[::1]:8443", PortalEndpoint.normalize("https://[::1]:8443"))
        for (bad in listOf("http://u:p@portal.example", "https://portal.example/path", "https://portal.example?q=p",
            "http://portal.example#x", "file:///etc/passwd", "http://127.01.0.1", "http://portal.example:",
            "http://portal.example:65536", "https://portal.example\n".replace("\n", "\nsecret"))) {
            assertNull(bad, PortalEndpoint.normalize(bad))
        }
    }

    @Test fun cleartextConsentIsExplicitAndBoundToOrigin() {
        val kv = InMemoryKeyValueStore()
        kv.putString(PortalConfig.KEY_PORTAL, "202.194.116.116")
        assertEquals("http://202.194.116.116", PortalConfig.read(kv))
        assertFalse(PortalConfig.allowsInsecureHttp(kv))
        PortalConfig.write(kv, "http://10.0.0.1", true)
        assertTrue(PortalConfig.allowsInsecureHttp(kv))
        PortalConfig.write(kv, "http://10.0.0.2")
        assertFalse(PortalConfig.allowsInsecureHttp(kv))
        PortalConfig.write(kv, "https://portal.example", true)
        assertFalse(PortalConfig.allowsInsecureHttp(kv))
    }

    @Test fun noRequestBeforeCleartextConsent() {
        var requests = 0
        val client = SrunAuthClient(engine = object : HttpEngine {
            override fun get(url: String, timeoutMs: Int): AuthResponse { requests++; error("must not request") }
        })
        val result = client.execute(AuthRequest("synthetic-user", "synthetic-pass", "5", "http://10.0.0.1"))
        assertEquals(AuthCodes.E_INSECURE_PORTAL, result.code)
        assertEquals(0, requests)
    }

    private class Connection(url: URL, private val code: Int = 200, private val body: ByteArray = "{}".toByteArray(),
        private val advertised: Long = -1) : HttpURLConnection(url) {
        var closed = false
        override fun connect() {}
        override fun usingProxy() = false
        override fun disconnect() { closed = true }
        override fun getResponseCode() = code
        override fun getContentLengthLong() = advertised
        override fun getInputStream() = ByteArrayInputStream(body)
        override fun getErrorStream() = ByteArrayInputStream(body)
    }
    private fun engine(connection: (URL) -> java.net.URLConnection?) = HttpUrlConnectionEngine(
        connectionFactory = object : ConnectionFactory { override fun open(url: URL) = connection(url) },
        retryCount = 0, maxResponseBytes = 32)

    @Test fun responseLimitChecksActualBytesAndClosesConnection() {
        lateinit var conn: Connection
        val engine = engine { Connection(it, body = ByteArray(33)).also { c -> conn = c } }
        fail { engine.get("https://portal.example/cgi-bin/get_challenge", 500) }
        assertTrue(conn.closed)
    }
    @Test fun advertisedOversizedResponseIsRejected() {
        fail { engine { Connection(it, advertised = 33) }.get("https://portal.example/", 500) }
    }
    @Test fun redirectIsNotFollowedAndConnectionIsClosed() {
        lateinit var conn: Connection
        fail { engine { Connection(it, 302).also { c -> conn = c } }.get("https://portal.example/", 500) }
        assertFalse(conn.instanceFollowRedirects)
        assertTrue(conn.closed)
    }
    @Test fun failedBindingCannotFallBackToDefaultNetwork() {
        fail { engine { null }.get("https://portal.example/", 500) }
        fail { engine { throw NetworkBindingException() }.get("https://portal.example/", 500) }
    }
    @Test fun credentialBearingLoginRequestIsNeverReplayed() {
        var attempts = 0
        val engine = HttpUrlConnectionEngine(connectionFactory = object : ConnectionFactory {
            override fun open(url: URL): java.net.URLConnection { attempts++; throw IOException("synthetic") }
        }, retryCount = 5, retryDelayMs = 0)
        fail { engine.get("https://portal.example/cgi-bin/srun_portal?password=secret", 500) }
        assertEquals(1, attempts)
    }
    @Test fun diagnosticsDoNotContainQueriesOrIoExceptionMessages() {
        val logs = mutableListOf<String>()
        val engine = HttpUrlConnectionEngine(connectionFactory = object : ConnectionFactory {
            override fun open(url: URL): java.net.URLConnection { throw IOException("private-password") }
        }, retryCount = 0, log = logs::add)
        fail { engine.get("https://portal.example/cgi-bin/srun_portal?password=private-password", 500) }
        assertFalse(logs.joinToString().contains("private-password"))
        assertFalse(logs.joinToString().contains("?"))
    }
    @Test fun malformedJsonCannotExhaustStackOrAcceptAmbiguousFields() {
        for (raw in listOf("[".repeat(40) + "0" + "]".repeat(40), "{\"error\":\"ok\",\"error\":\"bad\"}",
            "{\"x\":01}", "{\"x\":1.}", "{\"x\":1e}", "{\"x\":\"a\nb\"}", "callback({});evil()")) {
            assertNull(raw.take(50), Jsonp.tryParse(raw))
        }
        assertNotNull(Jsonp.tryParse("callback({\"error\":\"ok\"});"))
        assertNull(Jsonp.tryParse(" ".repeat(262145)))
    }
    @Test fun probeUsesRealHostAndConfiguredHttpsPort() {
        var host = ""; var port = 0
        val probe = SrunPortalProbe(object : HttpEngine {
            override fun get(url: String, timeoutMs: Int) = AuthResponse(200, "{\"error\":\"ok\",\"challenge\":\"synthetic\"}")
        }, ipProbe = object : LocalIpProbe {
            override fun probe(h: String, p: Int, timeoutMs: Int): String { host = h; port = p; return "10.0.0.2" }
        })
        assertEquals(ProbeOutcome.NOT_LOGGED_IN, probe.probe("https://portal.example:8443", "test", "").outcome)
        assertEquals("portal.example", host)
        assertEquals(8443, port)
    }
    @Test fun nonSuccessHttpCannotReportOnline() {
        assertEquals(ProbeOutcome.INDETERMINATE,
            SrunProbeClassifier.classify(503, "{\"error\":\"already online\"}").outcome)
    }
    @Test fun secureStorageRandomIvLegacyReadAndTamperProtection() {
        val secure = store(); val plain = "synthetic-secret".toByteArray()
        val first = secure.encrypt(plain); val second = secure.encrypt(plain)
        assertFalse(first.contentEquals(second)); assertArrayEquals(plain, secure.decrypt(first))
        val key = FixedSecretKeyProvider(ByteArray(32) { it.toByte() }).getOrCreate()
        val iv = ByteArray(12) { (it + 7).toByte() }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        assertArrayEquals(plain, secure.decrypt(byteArrayOf(0x53, 0x01) + iv + cipher.doFinal(plain)))
        first[first.lastIndex] = (first.last().toInt() xor 1).toByte()
        fail { secure.decrypt(first) }
    }
    @Test fun corruptedCredentialsCannotBeOverwrittenBySavingAnotherAccount() {
        val kv = InMemoryKeyValueStore(); kv.putString(AccountStore.KEY_ACCOUNTS, "damaged")
        val accounts = AccountStore(store(), kv)
        fail { accounts.save("campus", "label", "user", "pass") }
        assertEquals("damaged", kv.getString(AccountStore.KEY_ACCOUNTS))
    }
    @Test fun deletingLastAccountDoesNotResurrectLegacyCredentials() {
        val kv = InMemoryKeyValueStore(); val secure = store(); val accounts = AccountStore(secure, kv)
        accounts.save("campus", "label", "user", "pass")
        assertTrue(accounts.delete("campus"))
        assertTrue(AccountStore(secure, kv).list().isEmpty())
        assertTrue(CredentialRepository(secure, kv).list().isEmpty())
    }
    @Test fun sameLabelOnDifferentWifiKeepsCorrectCredentials() {
        val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("wifi-a", "same", "user-a", "pass-a")
        accounts.save("wifi-b", "same", "user-b", "pass-b")
        assertEquals("user-a", accounts.credentialForSsid("wifi-a")!!.username)
        assertEquals("user-b", accounts.credentialForSsid("wifi-b")!!.username)
        accounts.setEnabled("wifi-a", false)
        assertNull(accounts.credentialForSsid("wifi-a"))
    }
    @Test fun repositoryConcurrentWritesDoNotLoseAccounts() {
        val kv = InMemoryKeyValueStore(); val secure = store(); val pool = Executors.newFixedThreadPool(4)
        val start = CountDownLatch(1)
        val futures = (1..12).map { i -> pool.submit { start.await();
            AccountStore(secure, kv).save("wifi-$i", "label-$i", "user-$i", "pass-$i") } }
        try { start.countDown(); futures.forEach { it.get(10, TimeUnit.SECONDS) } }
        finally { pool.shutdownNow() }
        assertEquals(12, AccountStore(secure, kv).list().size)
    }
    @Test fun alreadyOnlineResetsBackoffAndNoWifiWaitsForEvents() {
        val scheduler = BackoffScheduler()
        assertEquals(ScheduleDecision.Done, scheduler.decide(
            AuthFlowOutcome.Skipped(AuthSkipReason.ALREADY_ONLINE, "campus", "campus"), 5, 0, 1000))
        val skip = scheduler.decide(AuthFlowOutcome.Skipped(AuthSkipReason.NO_CURRENT_SSID, null, null), 0, 0, 1000)
        assertEquals(0L, (skip as ScheduleDecision.RetrySoon).delaySeconds)
        assertTrue(scheduler.decide(done(AuthCodes.E_TLS), 0, 0, 1000) is ScheduleDecision.GiveUp)
        assertTrue(scheduler.decide(done("E2553", AuthFailure.REJECTED), 0, 0, 1000) is ScheduleDecision.GiveUp)
        assertTrue(scheduler.decide(done(AuthCodes.E_PORTAL), 0, 0, 1000) is ScheduleDecision.Backoff)
    }
    @Test fun preciseLocationCannotBeReplacedByNearbyOrCoarsePermission() {
        assertEquals(WifiPermissionState.DENIED, WifiPermissionPolicy.state(33,
            setOf(WifiPermissionPolicy.NEARBY_WIFI_DEVICES, "android.permission.ACCESS_COARSE_LOCATION")))
        assertEquals(WifiPermissionState.GRANTED, WifiPermissionPolicy.state(33,
            setOf(WifiPermissionPolicy.ACCESS_FINE_LOCATION)))
        assertTrue(WifiPermissionPolicy.requiredPermissions(31).contains("android.permission.ACCESS_COARSE_LOCATION"))
    }
    @Test fun logsRedactEncodedSecretsAndCredentialQueries() {
        assertFalse(AccountMask.redact("pw=a%2Bb", listOf("a+b")).contains("a%2Bb"))
        val text = AppLog.sanitize("GET https://portal.example/path?password=secret&info=encoded")
        assertFalse(text.contains("secret")); assertFalse(text.contains("encoded"))
        assertFalse(AppLog.sanitize("{\"password\":\"private\"}").contains("private"))
    }
    private fun flow(accounts: AccountStore, current: String?, session: AuthSessionFactory? = null,
        transport: AuthTransport = AuthTransport { AuthResult.success("verify", "synthetic", 0, "") }): AuthFlow = AuthFlow(
        credentials = object : CredentialLookup {
            override fun find(label: String): Credential? = null
            override fun selected(): Credential = Credential("wrong", "wrong-user", "wrong-pass", Carrier.YTU, "5")
        }, wifiMap = accounts, enabledAccounts = accounts,
        wifiSnapshot = object : WifiSnapshotPort { override fun currentSsid() = current },
        portalProvider = object : PortalProvider { override fun portal() = "https://portal.example" },
        transport = transport, sessionFactory = session)

    @Test fun flowUsesSsidCredentialAndClosesCapturedSession() {
        val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("campus-a", "same", "user-a", "pass-a")
        accounts.save("campus-b", "same", "user-b", "pass-b")
        var username = ""; var released = 0; var captured = ""
        val sessions = AuthSessionFactory { ssid ->
            captured = ssid
            AuthSession(AuthTransport { req -> username = req.username;
                AuthResult.success("verify", "synthetic", 1, "client_ip") }, ProbePort.inactive) { released++ }
        }
        val result = flow(accounts, "campus-a", sessions).run("campus-a")
        assertTrue(result is AuthFlowOutcome.Done && result.result.ok)
        assertEquals("user-a", username); assertEquals("campus-a", captured); assertEquals(1, released)
    }
    @Test fun unknownOrDisabledWifiNeverUsesSelectedCredential() {
        val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("campus", "label", "user", "pass", false)
        var requests = 0
        val transport = AuthTransport { requests++; error("must not send") }
        assertTrue(flow(accounts, "other", transport = transport).run(null) is AuthFlowOutcome.Skipped)
        assertTrue(flow(accounts, "campus", transport = transport).run(null) is AuthFlowOutcome.Skipped)
        assertEquals(0, requests)
    }
    @Test fun bindingFailureStopsBeforeProbeOrLogin() {
        val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("campus", "label", "user", "pass")
        val result = flow(accounts, "campus", AuthSessionFactory { throw NetworkBindingException() }).run(null)
        assertEquals(AuthCodes.E_WIFI_CHANGED, (result as AuthFlowOutcome.Done).result.code)
    }
    @Test fun concurrentManualAndBackgroundAuthenticationAreCoalesced() {
        val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("campus", "label", "user", "pass")
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val pool = Executors.newSingleThreadExecutor()
        val first = flow(accounts, "campus", transport = AuthTransport {
            entered.countDown(); check(release.await(5, TimeUnit.SECONDS));
            AuthResult.success("verify", "synthetic", 1, "")
        })
        val pending = pool.submit<AuthFlowOutcome> { first.run(null) }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val second = flow(accounts, "campus").run(null) as AuthFlowOutcome.Skipped
            assertEquals(AuthSkipReason.IN_PROGRESS, second.reason)
        } finally { release.countDown(); pending.get(5, TimeUnit.SECONDS); pool.shutdownNow() }
    }
    @Test fun terminalFailureSurvivesProcessRestartUntilConfigurationChanges() {
        val kv = InMemoryKeyValueStore(); val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("campus", "label", "user", "pass")
        var calls = 0
        val failed = AuthTransport { calls++; AuthResult.failure(AuthFailure.REJECTED, "E2553", "synthetic", "verify", 0) }
        val state = AuthStatusStore(kv)
        val first = AuthWorkCoordinator(flow(accounts, "campus", transport = failed), state, trigger = TriggerKind.NETWORK)
        assertEquals(RunOutcome.GIVE_UP, first.run("campus").outcome)
        val second = AuthWorkCoordinator(flow(accounts, "campus", transport = failed), AuthStatusStore(kv), trigger = TriggerKind.PERIODIC)
        assertEquals(RunOutcome.GIVE_UP, second.run("campus").outcome)
        assertEquals(1, calls)
        state.setUserActionRequired(false); state.clearAttempts(0)
        second.run("campus"); assertEquals(2, calls)
    }
    @Test fun legacyMigrationRetainsAllBoundWifiNetworks() {
        val kv = InMemoryKeyValueStore(); val secure = store()
        CredentialRepository(secure, kv).upsert(Credential("shared", "user", "pass", Carrier.YTU, "5"))
        WifiAccountMap(kv).bind("campus-a", "shared"); WifiAccountMap(kv).bind("campus-b", "shared")
        val migrated = AccountStore(secure, kv)
        assertNotNull(migrated.credentialForSsid("campus-a")); assertNotNull(migrated.credentialForSsid("campus-b"))
    }

    @Test fun ssidWhitespaceCannotMatchAnotherNetwork() {
        val accounts = AccountStore(store(), InMemoryKeyValueStore())
        accounts.save("campus", "label", "user", "pass")
        var calls = 0
        val result = flow(accounts, " campus ", transport = AuthTransport { calls++; error("wrong WiFi") }).run("campus")
        assertTrue(result is AuthFlowOutcome.Skipped); assertEquals(0, calls)
        val permissions = DefaultWifiPermissionFlow(33, setOf(WifiPermissionPolicy.ACCESS_FINE_LOCATION))
        val source = object : WifiSource {
            override fun isWifiEnabled() = true
            override fun currentSsidRaw() = "\" campus \""
            override fun scanSsidEntries() = listOf(WifiScanEntry(" campus ", -40), WifiScanEntry("campus", -30))
        }
        val snapshot = WifiSnapshotCore(source, permissions)
        assertEquals(" campus ", snapshot.currentSsid())
        assertEquals(2, snapshot.scanSsidList().size)
    }

}
