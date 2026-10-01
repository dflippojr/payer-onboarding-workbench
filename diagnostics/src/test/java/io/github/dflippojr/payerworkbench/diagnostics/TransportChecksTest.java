package io.github.dflippojr.payerworkbench.diagnostics;

import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.healthy;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.hook;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.only;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.orderSign;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.resource;
import static io.github.dflippojr.payerworkbench.diagnostics.Fixtures.unreachable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TransportChecksTest {

    private static final String PKIX = "javax.net.ssl.SSLHandshakeException: PKIX path building failed: "
            + "sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path "
            + "to requested target";
    private static final String CERT_REQUIRED =
            "javax.net.ssl.SSLHandshakeException: Received fatal alert: certificate_required";

    @Nested
    class Latency {
        private final LatencyCheck check = new LatencyCheck(Duration.ofSeconds(5), Duration.ofSeconds(10));

        @Test
        void fastCallsPass() {
            assertTrue(only(check.evaluate(healthy().build()), Severity.PASS).evidence().contains("slowest 800 ms"));
        }

        @Test
        void overWarnBudgetWarns() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(hook(200, resource("order-sign-healthy.json"), 6_500))));
            assertTrue(only(check.evaluate(run.build()), Severity.WARN).title().contains("6.5 s"));
        }

        @Test
        void overFailBudgetFails() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(hook(200, resource("order-sign-healthy.json"), 11_000))));
            only(check.evaluate(run.build()), Severity.FAIL);
        }

        @Test
        void timeoutFails() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(unreachable("POST", Fixtures.ORDER_SIGN_URL,
                    "java.net.http.HttpTimeoutException: request timed out"))));
            assertTrue(only(check.evaluate(run.build()), Severity.FAIL).title().contains("timed out"));
        }
    }

    @Nested
    class Tls {
        private final TlsHandshakeCheck check = new TlsHandshakeCheck();

        @Test
        void httpsExchangesPass() {
            Finding f = only(check.evaluate(healthy().build()), Severity.PASS);
            assertTrue(f.evidence().contains("crd.synthetic-payer.test"));
            assertTrue(f.evidence().contains("auth.synthetic-payer.test"));
        }

        @Test
        void untrustedServerCaFails() {
            var run = healthy();
            run.discovery = unreachable("GET", Fixtures.DISCOVERY_URL, PKIX);
            run.hooks = new ArrayList<>();
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Payer's TLS certificate is not trusted", f.title());
            assertTrue(f.suggestedFix().contains("trust store"));
        }

        @Test
        void missingClientCertificateFails() {
            var run = healthy();
            run.hooks = new ArrayList<>(List.of(orderSign(unreachable("POST", Fixtures.ORDER_SIGN_URL, CERT_REQUIRED))));
            Finding f = only(check.evaluate(run.build()), Severity.FAIL);
            assertEquals("Payer requires a client certificate (mutual TLS)", f.title());
            assertTrue(f.suggestedFix().contains("mtlsCredentialRef"));
        }

        @Test
        void rejectedClientCertificateFailsWhenMtlsConfigured() {
            var run = healthy();
            run.connection = Fixtures.connection("2.0.1", true);
            run.hooks = new ArrayList<>(List.of(orderSign(unreachable("POST", Fixtures.ORDER_SIGN_URL,
                    "javax.net.ssl.SSLHandshakeException: Received fatal alert: unknown_ca"))));
            assertEquals("Payer rejected the client certificate", only(check.evaluate(run.build()), Severity.FAIL).title());
        }

        @Test
        void classifiesCommonErrors() {
            assertEquals(TlsHandshakeCheck.Cause.HOSTNAME_MISMATCH, TlsHandshakeCheck.classify(
                    "java.security.cert.CertificateException: No subject alternative DNS name matching x.test found",
                    false));
            assertEquals(TlsHandshakeCheck.Cause.PROTOCOL_MISMATCH, TlsHandshakeCheck.classify(
                    "javax.net.ssl.SSLHandshakeException: Received fatal alert: protocol_version", false));
            assertNull(TlsHandshakeCheck.classify("java.net.ConnectException: Connection refused", false));
        }

        @Test
        void plainConnectionErrorIsNotTls() {
            var run = healthy();
            run.discovery = unreachable("GET", Fixtures.DISCOVERY_URL, "java.net.ConnectException: Connection refused");
            assertEquals(Severity.PASS, only(check.evaluate(run.build())).severity());
        }
    }
}
