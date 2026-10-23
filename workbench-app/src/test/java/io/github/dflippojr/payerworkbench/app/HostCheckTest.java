package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DNS rebinding (#201): a web page whose name the attacker rebinds to 127.0.0.1 reaches the workbench with
 * the attacker's name in {@code Host}. A raw socket sends it, because the JDK client won't set {@code Host}.
 * Custom endpoints are on, as in the README's local opt-in, because that is where rebinding turns the
 * workbench into a loopback port scanner.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.custom-endpoints.enabled=true")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HostCheckTest {

    static final String SYNTHETIC_RUN = """
            {"payerId":"northwind-synthetic","sampleId":"order-sign-hospital-bed"}""";

    @Autowired
    RunStore store;
    @Value("${local.server.port}")
    int port;

    @Test
    @Order(1)
    void foreignHostIsRefusedBeforeAnythingRuns() throws Exception {
        String host = "attacker.example:" + port;
        String loopbackScan = """
                {"sampleId":"order-sign-hospital-bed","customEndpoint":{"baseUrl":"http://127.0.0.1:%d/api/runs","authType":"NONE"}}"""
                .formatted(port);
        for (Response response : new Response[] {
                send(port, "GET", "/api/runs", host, null),
                send(port, "POST", "/api/runs", host, SYNTHETIC_RUN),
                send(port, "POST", "/api/runs", host, loopbackScan),
                send(port, "GET", "/actuator/health", host, null),
                send(port, "GET", "/actuator/prometheus", host, null),
                send(port, "GET", "/", host, null),
                send(port, "GET", "/api/runs", "ATTACKER.example", null)}) {
            assertEquals(403, response.status(), response.raw());
            assertTrue(response.raw().contains("application/problem+json"), response.raw());
            assertTrue(response.body().contains("workbench.allowed-hosts"), response.raw());
        }
        assertTrue(store.list().isEmpty(), "a refused request started a run");
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "127.0.0.1", "[::1]", "LOCALHOST"})
    @Order(2)
    void loopbackHostsStillWork(String name) throws Exception {
        String host = name + ":" + port;
        assertEquals(200, send(port, "GET", "/api/runs", host, null).status());
        assertEquals(200, send(port, "GET", "/actuator/health", host, null).status());
        assertEquals(200, send(port, "GET", "/", host, null).status());
        Response run = send(port, "POST", "/api/runs", host, SYNTHETIC_RUN);
        assertEquals(200, run.status(), run.raw());
        assertTrue(run.body().contains("\"runId\""), run.raw());
    }

    @Test
    @Order(3)
    void missingHostIsRefused() throws Exception {
        assertEquals(403, send(port, "GET", "/api/runs", null, null).status());
    }

    record Response(int status, String raw) {
        String body() {
            int split = raw.indexOf("\r\n\r\n");
            return split < 0 ? "" : raw.substring(split + 4);
        }
    }

    /** One HTTP/1.x request with exactly the {@code Host} given (none when null, as HTTP/1.0 allows). */
    static Response send(int port, String method, String path, String host, String json) throws IOException {
        byte[] body = json == null ? new byte[0] : json.getBytes(StandardCharsets.UTF_8);
        StringBuilder head = new StringBuilder(method).append(' ').append(path)
                .append(host == null ? " HTTP/1.0\r\n" : " HTTP/1.1\r\nHost: " + host + "\r\n");
        head.append("Connection: close\r\n");
        if (json != null) {
            head.append("Content-Type: application/json\r\nContent-Length: ").append(body.length).append("\r\n");
        }
        head.append("\r\n");
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(60_000);
            OutputStream out = socket.getOutputStream();
            out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
            out.write(body);
            out.flush();
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream received = new ByteArrayOutputStream();
            in.transferTo(received);
            String raw = received.toString(StandardCharsets.UTF_8);
            return new Response(Integer.parseInt(raw.substring(9, 12)), raw);
        }
    }
}
