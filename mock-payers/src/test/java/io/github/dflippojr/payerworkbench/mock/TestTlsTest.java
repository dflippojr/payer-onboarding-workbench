package io.github.dflippojr.payerworkbench.mock;

import org.junit.jupiter.api.Test;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.net.ssl.SSLHandshakeException;
import static org.junit.jupiter.api.Assertions.*;

class TestTlsTest {
    private static final Instant CREATED = Instant.parse("2026-03-01T12:00:00Z");
    private static final Instant TEN_YEARS_LATER = Instant.parse("2036-03-01T12:00:00Z");

    private static Clock createdAt(Instant instant) {
        return Clock.fixed(instant, ZoneOffset.UTC);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"healthy", "untrusted", "wrong-host"})
    void everyChainThatIsNotMeantToBeExpiredIsValidForTenYearsFromCreation(String alias) {
        for (X509Certificate certificate : new TestTls(createdAt(CREATED)).chain(alias)) {
            assertEquals(Date.from(TEN_YEARS_LATER), certificate.getNotAfter(), certificate.getSubjectX500Principal().getName());
        }
    }

    @Test
    void healthyChainValidatesAgainstTheTestCaUntilItsTenYearsEnd() throws Exception {
        X509Certificate[] healthy = new TestTls(createdAt(CREATED)).chain("healthy");
        validate(healthy, CREATED.plus(31, ChronoUnit.DAYS));
        validate(healthy, TEN_YEARS_LATER);
        assertThrows(CertPathValidatorException.class, () -> validate(healthy, TEN_YEARS_LATER.plusSeconds(1)));
    }

    @Test
    void expiredChainIsAlreadyPastItsEndWhenCreated() {
        X509Certificate leaf = new TestTls(createdAt(CREATED)).chain("expired")[0];
        assertEquals(Date.from(CREATED.minus(1, ChronoUnit.DAYS)), leaf.getNotAfter());
    }

    /** JSSE checks certificates against the live clock, so the workbench's start moves back instead. */
    @Test
    void tlsRun31DaysAfterWorkbenchStartStillGetsTheHealthyChain() throws Exception {
        TestTls tls = startedThirtyOneDaysAgo();
        try (MockPayer payer = FabrikamPayer.builder().build().tls(tls).start(0);
             HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build()) {
            var request = HttpRequest.newBuilder(URI.create(payer.baseUrl() + "/cds-services")).build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertEquals(tls.chain("healthy")[0], response.sslSession().orElseThrow().getPeerCertificates()[0]);
        }
    }

    /** A fault chain that had expired by itself would report expiry instead of the selected fault. */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "UNTRUSTED_CERTIFICATE, unable to find valid certification path",
            "EXPIRED_CERTIFICATE, NotAfter",
            "HOSTNAME_MISMATCH, No subject alternative"})
    void tlsRun31DaysAfterWorkbenchStartStillFailsForTheSelectedFault(Fault fault, String reason) throws Exception {
        TestTls tls = startedThirtyOneDaysAgo();
        try (MockPayer payer = FabrikamPayer.builder().build().tls(tls).start(0);
             HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build()) {
            var request = HttpRequest.newBuilder(URI.create(payer.baseUrl() + "/cds-services")).build();
            payer.faults().enable(fault);
            SSLHandshakeException failure = assertThrows(SSLHandshakeException.class,
                    () -> client.send(request, HttpResponse.BodyHandlers.ofString()));
            assertTrue(causes(failure).contains(reason), causes(failure));
        }
    }

    private static TestTls startedThirtyOneDaysAgo() {
        return new TestTls(Clock.offset(Clock.systemUTC(), Duration.ofDays(-31)));
    }

    private static String causes(Throwable failure) {
        StringBuilder text = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            text.append(t).append('\n');
        }
        return text.toString();
    }

    private static void validate(X509Certificate[] chain, Instant at) throws Exception {
        PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(chain[chain.length - 1], null)));
        parameters.setRevocationEnabled(false);
        parameters.setDate(Date.from(at));
        CertPathValidator.getInstance("PKIX").validate(
                CertificateFactory.getInstance("X.509").generateCertPath(List.of(chain[0])), parameters);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = Fault.class,
            names = {"UNTRUSTED_CERTIFICATE", "EXPIRED_CERTIFICATE", "HOSTNAME_MISMATCH"})
    void selectedCertificateFailsBeforeHttpAndClearingRestoresTrust(Fault fault) throws Exception {
        TestTls tls = new TestTls();
        try (MockPayer payer = FabrikamPayer.builder().build().tls(tls).start(0)) {
            var request = HttpRequest.newBuilder(URI.create(payer.baseUrl() + "/cds-services")).build();
            payer.faults().enable(fault);
            try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build()) {
                assertThrows(SSLHandshakeException.class, () -> client.send(request, HttpResponse.BodyHandlers.ofString()));
            }
            payer.faults().clear();
            try (HttpClient client = HttpClient.newBuilder().sslContext(tls.clientContext()).build()) {
                assertEquals(200, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
            }
        }
    }

    @Test
    void testCaIsPrivateAndBothLoopbackNamesAreValid() throws Exception {
        TestTls tls = new TestTls();
        try (MockPayer payer = NorthwindPayer.builder().client("demo", StandaloneArgs.randomSecret()).build().tls(tls).start(0);
             HttpClient trusted = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
             HttpClient defaultTrust = HttpClient.newHttpClient();
             HttpClient otherCa = HttpClient.newBuilder().sslContext(new TestTls().clientContext()).build()) {
            for (String base : new String[]{payer.baseUrl(), payer.baseUrl().replace("127.0.0.1", "localhost")}) {
                var request = HttpRequest.newBuilder(URI.create(base + "/cds-services")).build();
                assertEquals(200, trusted.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
                assertThrows(SSLHandshakeException.class, () -> defaultTrust.send(request, HttpResponse.BodyHandlers.ofString()));
                assertThrows(SSLHandshakeException.class, () -> otherCa.send(request, HttpResponse.BodyHandlers.ofString()));
            }
            assertThrows(IllegalStateException.class, () -> payer.tls(tls));
        }
    }
}
