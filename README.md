# safari-issues
Proof of concept web application demonstrating a couple of Safari issues

This is a basic web application which embeds the Jetty Web Server and serves a few basic resources:

- `/` or `/index.html` - main entrypoint HTML web page which loads a basic javascript and css resource
- `/websocket.js` - javascript source code used to run the client side of the web socket in the web browser
- `main.css` - stylesheet used to style the `index.html` web page
- `/ws` - web socket endpoint which simply echoes whatever text messages are sent to it

This code builds off of the [Embedded Jetty Websocket Echo Server](https://github.com/jetty-project/embedded-websocket-echo-examples) example project.

The web application may be run using the included gradle wrapper:

`gradlew run` if on *nix or `gradlew.bat run` if on windows

Use the `--args="config.properties"` arg to pass the path to your configuration file (replace `config.properties` with the path to your java properties file, or simply use the included `config.properties` file at the root of this project and uncomment the lines you wish to build upon)

See the included `config.properties` file for details about each property

Detailed information about the configured Jetty web server is displayed to stdout on application startup and shutdown.

Before running the web application, make sure your `JAVA_HOME` is set to a valid Java 11 JRE.

## Issue #1 - Basic Authentication with Web Sockets
If the web application is set up to require basic authentication to access all of its resources, Safari will be unable to connect to a websocket endpoint with the same protection.

When the upgrade request is made to `/ws`, the web application returns a 401 error code since Safari does not add the `Authorization: Basic ...` request header to the upgrade request. Chrome and Firefox both add the header and everything works as expected.

To enable basic authentication in the web application, edit your `config.properties` file and set the `basic.auth` property value to `true` and restart the application. Credentials are hard-coded to `admin` / `password`.

This issue appears to be logged here: https://bugs.webkit.org/show_bug.cgi?id=80362

## Issue #2 - TLS 1.3 with Web Sockets
If the web application is set up to require TLS 1.3 exclusively, Safari is unable to connect to the secure web socket endpoint using `wss://<host>:<port>/ws`. From a wireshark capture, it appears that Safari is attempting a TLS 1.2 handshake on servlet upgrade requests and since the web application only allows TLS 1.3, the connection is rejected. The only error in the Safari console is the following:

`WebSocket network error: The operation couldn’t be completed. (OSStatus error -9836.)`

This is not a problem in the latest Chrome or Firefox versions.

To enable TLS 1.3 exclusively in the web application, edit your `config.properties` file and set the following property:

`tls.easy.mode=TLSv1.3`

This is equivalent to leaving the above property commented-out and setting the following more advanced properties:

`tls.protocols.include=TLSv1.3`  
`tls.protocols.exclude=SSLv3,SSLv2Hello,TLSv1,TLSv1.1,TLSv1.2`  
`tls.ciphersuites.include=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256`  
`tls.ciphersuites.exclude=^.*_(MD5|SHA|SHA1)$,^TLS_RSA_.*$,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_EMPTY_RENEGOTIATION_INFO_SCSV`  

To enable TLS 1.2 and TLS 1.3 concurrently in the web application, edit your `config.properties` file and set the following property:

`tls.easy.mode=TLSv1.2,TLSv1.3`

This is equivalent to leaving the above property commented-out and setting the following more advanced properties:

`tls.protocols.include=TLSv1.2,TLSv1.3`  
`tls.protocols.exclude=SSLv3,SSLv2Hello,TLSv1,TLSv1.1`  
`tls.ciphersuites.include=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384`  
`tls.ciphersuites.exclude=^.*_(MD5|SHA|SHA1)$,^TLS_RSA_.*$,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_EMPTY_RENEGOTIATION_INFO_SCSV`  

The lines mentioned above are already provided in the sample `config.properties`, just uncomment the set you'd like to use.

In addition to the above properties, be sure to set the `keystore.path` property to the path to the key store file which contains the private key and certificate chain required for the web application's server-side SSL / TLS socket. The key store password, private key entry alias, and private key entry password may each be set using the `keystore.password`, `keystore.entry.alias`, and `keystore.entry.password` properties, respectively. The app comes bundled with a self-signed certificate in the `keystore.jks` key store file at the root of the project if you'd like to use that to test the configuration out before pointing to your own key store. The passwords / alias are the defaults set in the properties file.

Both of the above issues were tested using Safari 14.0.3.
