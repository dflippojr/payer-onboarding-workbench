package io.github.dflippojr.payerworkbench.app;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A loopback server sends bodies of known size; nothing leaves the machine. */
class ResponseLimitClientTest {

    private static final int LIMIT = 1000;

    private HttpServer server;
    private HttpClient http;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/size", exchange -> {
            int size = Integer.parseInt(exchange.getRequestURI().getQuery());
            byte[] body = "x".repeat(size).getBytes(StandardCharsets.US_ASCII);
            exchange.getResponseHeaders().set("X-Payer", "synthetic");
            exchange.sendResponseHeaders(201, 0);
            try (var out = exchange.getResponseBody()) {
                // Several small writes, so the limit falls inside a batch of buffers.
                for (int i = 0; i < body.length; i += 300) {
                    out.write(body, i, Math.min(300, body.length - i));
                    out.flush();
                }
            } catch (IOException e) {
                // The client stopped reading at its limit.
            }
        });
        server.createContext("/cards", exchange -> {
            int cards = Integer.parseInt(exchange.getRequestURI().getQuery());
            byte[] body = ("{\"cards\":[" + "{},".repeat(cards - 1) + "{}]}").getBytes(StandardCharsets.US_ASCII);
            exchange.getResponseHeaders().set("X-Payer", "synthetic");
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        http = HttpClient.newHttpClient();
    }

    @AfterEach
    void stop() {
        http.close();
        server.stop(0);
    }

    @Test
    void bodiesUpToTheLimitPassThroughUnchanged() throws Exception {
        ResponseLimitClient client = new ResponseLimitClient(http, LIMIT);
        for (int size : new int[] {0, 1, LIMIT}) {
            HttpResponse<String> response = client.send(request(size), HttpResponse.BodyHandlers.ofString());
            assertEquals(201, response.statusCode());
            assertEquals("x".repeat(size), response.body());
        }
        HttpResponse<byte[]> bytes = client.sendAsync(request(LIMIT), HttpResponse.BodyHandlers.ofByteArray()).get();
        assertEquals(LIMIT, bytes.body().length);
    }

    @Test
    void longerBodyFailsWithWhatArrivedUpToTheLimit() {
        ResponseLimitClient client = new ResponseLimitClient(http, LIMIT);

        ResponseTooLargeException e = assertThrows(ResponseTooLargeException.class,
                () -> client.send(request(50_000), HttpResponse.BodyHandlers.ofString()));

        assertEquals(LIMIT, e.limit());
        assertTrue(e.bytesRead() > LIMIT && e.bytesRead() < 50_000, "read " + e.bytesRead());
        assertEquals(201, e.statusCode());
        assertEquals("synthetic", e.headers().firstValue("X-Payer").orElseThrow());
        assertEquals("x".repeat(LIMIT), e.truncatedBody());
        assertEquals("[truncated at 1000 bytes]", e.note());
        assertTrue(e.getMessage().contains("exceeded the 1000 bytes limit"), e.getMessage());
        assertSame(e, ResponseTooLargeException.in(new IOException("wrapped", e)));
    }

    @Test
    void asyncCallsAndNonStringBodiesAreLimitedToo() {
        ResponseLimitClient client = new ResponseLimitClient(http, LIMIT);

        ExecutionException e = assertThrows(ExecutionException.class,
                () -> client.sendAsync(request(5000), HttpResponse.BodyHandlers.ofByteArray(), null).get());

        ResponseTooLargeException tooLarge = ResponseTooLargeException.in(e);
        assertInstanceOf(ResponseTooLargeException.class, tooLarge, String.valueOf(e.getCause()));
        assertNull(tooLarge.truncatedBody(), "only a string body is kept");
    }

    @Test
    void bodyWithTooManyJsonValuesFailsBeforeAnythingParsesIt() throws Exception {
        // A small body can still hold many values: the object, the array and each card count (#162).
        ResponseLimitClient client = new ResponseLimitClient(http, 1_000_000, 5000);
        assertEquals(200, client.send(cards(4998), HttpResponse.BodyHandlers.ofString()).statusCode());

        ResponseTooLargeException e = assertThrows(ResponseTooLargeException.class,
                () -> client.send(cards(4999), HttpResponse.BodyHandlers.ofString()));

        assertEquals(ResponseTooLargeException.Measure.JSON_VALUES, e.measure());
        assertEquals("5000 JSON values", e.describeLimit());
        assertEquals("workbench.max-response-json-values", e.setting());
        assertEquals(200, e.statusCode());
        assertEquals("synthetic", e.headers().firstValue("X-Payer").orElseThrow());
        assertEquals("{\"cards\":[]}".length() + 3 * 4999 - 1, e.bytesRead());
        assertEquals(ResponseTooLargeException.JSON_VALUES_PREFIX_CHARS, e.truncatedBody().length());
        assertTrue(e.truncatedBody().startsWith("{\"cards\":[{},{},"), e.truncatedBody().substring(0, 20));
        assertEquals("[not parsed: more than 5000 JSON values; kept the first 8192 characters]", e.note());
        assertTrue(e.getMessage().contains("more than 5000 JSON values"), e.getMessage());

        ExecutionException async = assertThrows(ExecutionException.class,
                () -> client.sendAsync(cards(4999), HttpResponse.BodyHandlers.ofString()).get());
        assertEquals(ResponseTooLargeException.Measure.JSON_VALUES, ResponseTooLargeException.in(async).measure());
    }

    @Test
    void countsEveryKindOfJsonValueAndStopsWhereTheTextStopsBeingJson() {
        String six = "{\"a\":[1,\"b\",null,true]}";
        assertTrue(ResponseLimitClient.holdsMoreJsonValuesThan(six, 5));
        assertFalse(ResponseLimitClient.holdsMoreJsonValuesThan(six, 6));
        assertFalse(ResponseLimitClient.holdsMoreJsonValuesThan("x".repeat(100), 1));
        assertTrue(ResponseLimitClient.holdsMoreJsonValuesThan("[" + "0,".repeat(10) + "oops", 9));
        assertFalse(ResponseLimitClient.holdsMoreJsonValuesThan("[" + "0,".repeat(10) + "oops", 11));
    }

    @Test
    void describesLimitsInTheLargestWholeUnit() {
        assertEquals("4 MiB", ResponseTooLargeException.describe(4L * 1024 * 1024));
        assertEquals("512 KiB", ResponseTooLargeException.describe(512 * 1024));
        assertEquals("1000 bytes", ResponseTooLargeException.describe(1000));
        assertNull(ResponseTooLargeException.in(new IOException("other")));
        assertThrows(IllegalArgumentException.class, () -> new ResponseLimitClient(http, 0));
    }

    @Test
    void theSettingDefaultsToFourMibAndMustBePositive() {
        assertEquals(4L * 1024 * 1024, new WorkbenchProperties(null, null, null, null, null).maxResponseBytes());
        assertThrows(IllegalArgumentException.class,
                () -> new WorkbenchProperties(null, null, null, null, null, null, null, 0L));
        assertEquals(100_000, new WorkbenchProperties(null, null, null, null, null).maxResponseJsonValues());
        assertThrows(IllegalArgumentException.class,
                () -> new WorkbenchProperties(null, null, null, null, null, null, null, null, null, 0));
        assertThrows(IllegalArgumentException.class, () -> new ResponseLimitClient(http, 1, 0));
    }

    private HttpRequest cards(int count) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/cards?" + count))
                .build();
    }

    private HttpRequest request(int size) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/size?" + size))
                .build();
    }
}
