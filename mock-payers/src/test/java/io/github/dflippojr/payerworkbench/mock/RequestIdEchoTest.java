package io.github.dflippojr.payerworkbench.mock;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpResponse;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Both payers echo and log a well-formed {@code X-Request-Id}, on success and on error. */
class RequestIdEchoTest {

    private static final String ID = "3f2b8c1e-5d4a-4e9b-9a77-0c1d2e3f4a5b";

    @ParameterizedTest
    @ValueSource(strings = {"northwind", "fabrikam"})
    void echoesAndLogsTheRequestId(String payerName) throws Exception {
        List<String> logged = new ArrayList<>();
        Logger logger = Logger.getLogger(MockPayer.class.getName());
        Handler capture = new Handler() {
            @Override
            public void publish(LogRecord record) {
                logged.add(MessageFormat.format(record.getMessage(), record.getParameters()));
            }

            @Override
            public void flush() {
                // nothing buffered
            }

            @Override
            public void close() {
                // nothing to release
            }
        };
        logger.addHandler(capture);
        try (PayerFixture fixture = PayerFixture.create(payerName)) {
            HttpResponse<String> discovery = fixture.raw("GET", "/cds-services", null, MockPayer.REQUEST_ID_HEADER, ID);
            HttpResponse<String> missing = fixture.raw("POST", "/cds-services/nope", "{}", MockPayer.REQUEST_ID_HEADER, ID);

            assertEquals(200, discovery.statusCode());
            assertEquals(ID, discovery.headers().firstValue(MockPayer.REQUEST_ID_HEADER).orElse(null));
            assertEquals(404, missing.statusCode());
            assertEquals(ID, missing.headers().firstValue(MockPayer.REQUEST_ID_HEADER).orElse(null));
        } finally {
            logger.removeHandler(capture);
        }
        assertTrue(logged.stream().anyMatch(l -> l.contains("GET /cds-services -> 200 requestId=" + ID)), logged::toString);
        assertTrue(logged.stream().anyMatch(l -> l.contains("POST /cds-services/nope -> 404 requestId=" + ID)),
                logged::toString);
    }

    @Test
    void ignoresMalformedOrMissingIds() throws Exception {
        try (PayerFixture fixture = PayerFixture.northwind()) {
            HttpResponse<String> forged = fixture.raw("GET", "/cds-services", null,
                    MockPayer.REQUEST_ID_HEADER, "abc def <script>");
            HttpResponse<String> none = fixture.raw("GET", "/cds-services", null);

            assertEquals(200, forged.statusCode());
            assertTrue(forged.headers().firstValue(MockPayer.REQUEST_ID_HEADER).isEmpty());
            assertTrue(none.headers().firstValue(MockPayer.REQUEST_ID_HEADER).isEmpty());
        }
        assertNull(MockPayer.requestId("x".repeat(129)));
        assertNull(MockPayer.requestId("line\nbreak"));
        assertEquals("run-1", MockPayer.requestId("run-1"));
    }
}
