/**
 * Universal Android SSL Pinning Bypass Hook Script
 *
 * Dedicated tool for security analysts auditing APKs that employ certificate
 * pinning (OkHttp CertificatePinner, TrustManager, NetworkSecurityConfig).
 *
 * Designed to be loaded via Frida alongside or independently of sensitive_apis.js.
 * All hooks are defensive (try/catch per component) to ensure broad compatibility
 * across Android 7.0 to Android 14+ without process crashing.
 */
(function () {
    "use strict";

    if (typeof Java === "undefined" || !Java.available) {
        return;
    }

    Java.perform(function () {
        var bypassed = [];
        var failed = [];

        // 1. Universal TrustManager bypass
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            var TrustManagerImpl = Java.registerClass({
                name: "com.adsdk.agent.CustomTrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () {
                        return [];
                    }
                }
            });

            var TrustManagers = [TrustManagerImpl.$new()];
            var sslContextInit = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            );
            sslContextInit.implementation = function (keyManager, trustManager, secureRandom) {
                sslContextInit.call(this, keyManager, TrustManagers, secureRandom);
            };
            bypassed.push("javax.net.ssl.SSLContext.init");
        } catch (e) {
            failed.push("javax.net.ssl.SSLContext");
        }

        // 2. OkHttp 3 & 4 CertificatePinner
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            if (CertificatePinner.check) {
                var checkOverloads = CertificatePinner.check.overloads;
                for (var i = 0; i < checkOverloads.length; i++) {
                    checkOverloads[i].implementation = function () {
                        // Suppress pin validation exception
                        return;
                    };
                }
                bypassed.push("okhttp3.CertificatePinner.check");
            }
        } catch (e) {
            // Target app might not use OkHttp3 or is obfuscated
            failed.push("okhttp3.CertificatePinner");
        }

        // 3. Android NetworkSecurityConfig pinning
        try {
            var NetworkSecurityTrustManager = Java.use(
                "android.security.net.config.NetworkSecurityTrustManager"
            );
            if (NetworkSecurityTrustManager.checkPins) {
                NetworkSecurityTrustManager.checkPins.implementation = function (pins) {
                    return;
                };
                bypassed.push("android.security.net.config.NetworkSecurityTrustManager.checkPins");
            }
        } catch (e) {
            failed.push("NetworkSecurityTrustManager");
        }

        // 4. Conscrypt Platform checkServerTrusted
        try {
            var ConscryptPlatform = Java.use("com.android.org.conscrypt.Platform");
            if (ConscryptPlatform.checkServerTrusted) {
                ConscryptPlatform.checkServerTrusted.overload(
                    "javax.net.ssl.X509TrustManager",
                    "[Ljava.security.cert.X509Certificate;",
                    "java.lang.String",
                    "com.android.org.conscrypt.AbstractConscryptSocket"
                ).implementation = function (tm, chain, authType, soc) {
                    return;
                };
                bypassed.push("conscrypt.Platform.checkServerTrusted");
            }
        } catch (e) {
            failed.push("conscrypt.Platform");
        }

        // 5. WebViewClient onReceivedSslError
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            if (WebViewClient.onReceivedSslError) {
                WebViewClient.onReceivedSslError.overload(
                    "android.webkit.WebView",
                    "android.webkit.SslErrorHandler",
                    "android.net.http.SslError"
                ).implementation = function (view, handler, error) {
                    handler.proceed();
                };
                bypassed.push("android.webkit.WebViewClient.onReceivedSslError");
            }
        } catch (e) {
            failed.push("WebViewClient.onReceivedSslError");
        }

        try {
            send({
                type: "control",
                event: "ssl_unpinning_status",
                bypassed: bypassed,
                failed: failed
            });
        } catch (_ignore) {}
    });
})();
