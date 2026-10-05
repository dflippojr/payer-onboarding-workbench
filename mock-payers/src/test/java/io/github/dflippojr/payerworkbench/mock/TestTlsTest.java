package io.github.dflippojr.payerworkbench.mock;

import org.junit.jupiter.api.Test;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import javax.net.ssl.SSLHandshakeException;
import static org.junit.jupiter.api.Assertions.*;

class TestTlsTest {
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
