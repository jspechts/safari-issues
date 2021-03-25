@file:JvmName("App")

package org.example

import org.eclipse.jetty.security.ConstraintMapping
import org.eclipse.jetty.security.ConstraintSecurityHandler
import org.eclipse.jetty.security.HashLoginService
import org.eclipse.jetty.security.UserStore
import org.eclipse.jetty.security.authentication.BasicAuthenticator
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.session.DefaultSessionCache
import org.eclipse.jetty.server.session.DefaultSessionIdManager
import org.eclipse.jetty.server.session.NullSessionDataStore
import org.eclipse.jetty.server.session.SessionHandler
import org.eclipse.jetty.servlet.ServletContextHandler
import org.eclipse.jetty.servlet.ServletHolder
import org.eclipse.jetty.util.security.Constraint
import org.eclipse.jetty.util.security.Credential
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.eclipse.jetty.websocket.api.Session
import org.eclipse.jetty.websocket.api.WebSocketAdapter
import org.eclipse.jetty.websocket.servlet.WebSocketServlet
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.*
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

private val LOG = LoggerFactory.getLogger("App")

class StaticResourceServlet : HttpServlet() {

    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        val path = req.requestURI.toString()
        val resourceName: String
        val contentType: String
        if (path.isBlank() || "/" == path || "/index.html".equals(path, true)) {
            resourceName = "/index.html"
            contentType = "text/html"
        } else if ("/websocket.js".equals(path, true)) {
            resourceName = "/websocket.js"
            contentType = "text/javascript"
        } else if ("/main.css".equals(path, true)) {
            resourceName = "/main.css"
            contentType = "text/css"
        } else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND)
            return
        }
        resp.contentType = contentType
        resp.characterEncoding = StandardCharsets.UTF_8.toString()
        javaClass.getResourceAsStream(resourceName).transferTo(resp.outputStream)
    }

}

class EchoSocket : WebSocketAdapter() {

    override fun onWebSocketConnect(session: Session) {
        super.onWebSocketConnect(session)
        LOG.info("WebSocket Connect: {}", session)
        remote.sendStringByFuture("You are now connected to ${javaClass.name}")
    }

    override fun onWebSocketClose(statusCode: Int, reason: String?) {
        super.onWebSocketClose(statusCode, reason)
        LOG.info("WebSocket Close: {} - {}", statusCode, reason)
    }

    override fun onWebSocketError(cause: Throwable) {
        super.onWebSocketError(cause)
        LOG.warn("WebSocket Error", cause)
    }

    override fun onWebSocketText(message: String?) {
        if (isConnected) {
            LOG.info("Echoing back text message [{}]", message)
            remote.sendStringByFuture(message)
        }
    }

    override fun onWebSocketBinary(payload: ByteArray?, offset: Int, len: Int) {
        /* ignore */
    }

}

class WebSocketServletImpl : WebSocketServlet() {

    override fun configure(factory: WebSocketServletFactory) {
        factory.register(EchoSocket::class.java)
    }

}

enum class TLSEasyMode(
    val includedProtocols: Array<String>,
    val excludedProtocols: Array<String>,
    val includedCipherSuites: Array<String>,
    val excludedCipherSuites: Array<String>
) {

    TLSV12(
        arrayOf("TLSv1.2"),
        arrayOf("SSLv3", "SSLv2Hello", "TLSv1", "TLSv1.1", "TLSv1.3"),
        arrayOf(
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
        ),
        arrayOf(
            "^.*_(MD5|SHA|SHA1)\$",
            "^TLS_RSA_.*\$",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        )
    ),
    TLSV13(
        arrayOf("TLSv1.3"),
        arrayOf("SSLv3", "SSLv2Hello", "TLSv1", "TLSv1.1", "TLSv1.2"),
        arrayOf("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"),
        arrayOf(
            "^.*_(MD5|SHA|SHA1)\$",
            "^TLS_RSA_.*\$",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        )
    );

    companion object {
        fun parse(str: String?): EnumSet<TLSEasyMode> {
            if (str == null) {
                return EnumSet.noneOf(TLSEasyMode::class.java)
            }
            val modes = str.split(",").mapNotNull {
                when {
                    "TLSv1.2".equals(it, false) -> {
                        TLSV12
                    }
                    "TLSv1.3".equals(it, false) -> {
                        TLSV13
                    }
                    else -> {
                        null
                    }
                }
            }
            return EnumSet.copyOf(modes)
        }
    }

}

fun main(args: Array<String>) {
    val server = Server()
    server.stopAtShutdown = true
    server.isDumpAfterStart = true
    server.isDumpBeforeStop = true

    val properties = Properties()
    if (args.isNotEmpty()) {
        val propertiesPathStr = args[0]
        val propertiesFilePath = Path.of(propertiesPathStr)
        Files.newInputStream(propertiesFilePath).use { fis -> properties.load(fis) }
    }

    val connector = ServerConnector(server)
    connector.host = properties.getProperty("http.host", "localhost")
    connector.port = Integer.parseInt(properties.getProperty("http.port", "0"))
    connector.reuseAddress = false

    server.addConnector(connector)

    val keystorePath = properties.getProperty("keystore.path")
    if (keystorePath != null) {
        val serverSslContextFactory = SslContextFactory.Server()
        serverSslContextFactory.keyStorePath = keystorePath

        val keystoreType = properties.getProperty("keystore.type")
        if (keystoreType != null) {
            serverSslContextFactory.keyStoreType = keystoreType
        }

        val keystoreEntryAlias = properties.getProperty("keystore.entry.alias")
        if (keystoreEntryAlias != null) {
            serverSslContextFactory.certAlias = keystoreEntryAlias
        }

        val keystorePassword = properties.getProperty("keystore.password")
        if (keystorePassword != null) {
            serverSslContextFactory.setKeyStorePassword(keystorePassword)
        }

        val keystoreEntryPassword = properties.getProperty("keystore.entry.password")
        if (keystoreEntryPassword != null) {
            serverSslContextFactory.setKeyManagerPassword(keystoreEntryPassword)
        }

        val easyMode = properties.getProperty("tls.easy.mode")
        val easyModes = TLSEasyMode.parse(easyMode)
        if (easyModes.isEmpty()) {
            val includedProtocols = properties.getProperty("tls.protocols.include")
            if (includedProtocols != null) {
                serverSslContextFactory.setIncludeProtocols(
                    *includedProtocols.split(",").map { it.trim() }.toTypedArray()
                )
            }

            val excludedProtocols = properties.getProperty("tls.protocols.exclude")
            if (excludedProtocols != null) {
                serverSslContextFactory.setExcludeProtocols(
                    *excludedProtocols.split(",").map { it.trim() }.toTypedArray()
                )
            }

            val includedCipherSuites = properties.getProperty("tls.ciphersuites.include")
            if (includedCipherSuites != null) {
                serverSslContextFactory.setIncludeCipherSuites(
                    *includedCipherSuites.split(",").map { it.trim() }.toTypedArray()
                )
            }

            val excludedCipherSuites = properties.getProperty("tls.ciphersuites.exclude")
            if (excludedCipherSuites != null) {
                serverSslContextFactory.setExcludeCipherSuites(
                    *excludedCipherSuites.split(",").map { it.trim() }.toTypedArray()
                )
            }
        } else {
            val includedProtocols = easyModes.asSequence()
                .map { it.includedProtocols }
                .map { it.toList() }
                .flatten()
                .toSet()
                .toTypedArray()
            val excludedProtocols = easyModes.asSequence()
                .map { it.excludedProtocols }
                .map { it.toList() }
                .flatten()
                .toSet()
                .minus(includedProtocols)
                .toTypedArray()
            val includedCipherSuites = easyModes.asSequence()
                .map { it.includedCipherSuites }
                .map { it.toList() }
                .flatten()
                .toSet()
                .toTypedArray()
            val excludedCipherSuites = easyModes.asSequence()
                .map { it.excludedCipherSuites }
                .map { it.toList() }
                .flatten()
                .toSet()
                .minus(includedCipherSuites)
                .toTypedArray()

            serverSslContextFactory.setIncludeProtocols(*includedProtocols)
            serverSslContextFactory.setExcludeProtocols(*excludedProtocols)
            serverSslContextFactory.setIncludeCipherSuites(*includedCipherSuites)
            serverSslContextFactory.setExcludeCipherSuites(*excludedCipherSuites)
        }

        serverSslContextFactory.isRenegotiationAllowed = false

        val secureConnector = ServerConnector(server, serverSslContextFactory)
        secureConnector.host = properties.getProperty("https.host", "localhost")
        secureConnector.port = Integer.parseInt(properties.getProperty("https.port", "0"))
        secureConnector.reuseAddress = false

        server.addConnector(secureConnector)
    }

    val sessionIdManager = DefaultSessionIdManager(server)
    server.sessionIdManager = sessionIdManager

    val sessionHandler = SessionHandler()
    sessionHandler.sessionIdManager = sessionIdManager
    val sessionCache = DefaultSessionCache(sessionHandler)
    val sessionDataStore = NullSessionDataStore()
    sessionCache.sessionDataStore = sessionDataStore
    sessionHandler.sessionCache = sessionCache

    val servletContextHandler = ServletContextHandler()
    servletContextHandler.sessionHandler = sessionHandler

    val webSocketServlet = WebSocketServletImpl()
    val webSocketServletHolder = ServletHolder()
    webSocketServletHolder.servlet = webSocketServlet
    servletContextHandler.addServlet(webSocketServletHolder, "/ws")

    val staticResourceServlet = StaticResourceServlet()
    val staticResourceServletHolder = ServletHolder()
    staticResourceServletHolder.servlet = staticResourceServlet
    servletContextHandler.addServlet(staticResourceServletHolder, "/*")

    if (properties.getProperty("basic.auth", "false").toBoolean()) {
        val userStore = UserStore()
        userStore.addUser("admin", Credential.getCredential("password"), arrayOf("Administrator"))

        val loginService = HashLoginService("realm")
        loginService.setUserStore(userStore)

        val securityHandler = ConstraintSecurityHandler()
        securityHandler.authenticator = BasicAuthenticator()
        securityHandler.realmName = "realm"
        securityHandler.loginService = loginService

        val constraint = Constraint()
        constraint.name = Constraint.__BASIC_AUTH
        constraint.roles = arrayOf("Administrator")
        constraint.authenticate = true

        val constraintMapping = ConstraintMapping()
        constraintMapping.constraint = constraint
        constraintMapping.pathSpec = "/*"
        securityHandler.addConstraintMapping(constraintMapping)

        servletContextHandler.securityHandler = securityHandler
    }

    server.handler = servletContextHandler

    server.start()
    server.join()
}
