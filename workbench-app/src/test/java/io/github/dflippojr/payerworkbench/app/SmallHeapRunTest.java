package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * One payer response under {@code workbench.max-response-bytes} can still hold a million small JSON
 * values. This starts the app in its own JVM with a small heap, the way a reviewer exhausted 512 MiB
 * with 1.4 million empty cards in one run (#162), and checks the run is answered and stays small.
 * A second test sends many near-limit runs at once, and a payer that never finishes its body.
 */
class SmallHeapRunTest {

    private static final String HEAP = "-Xmx256m";
    private static final Pattern PORT = Pattern.compile("started on port (\\d+)");

    @TempDir
    Path data;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private Process app;
    /** The app's console output so far. */
    private final StringBuffer output = new StringBuffer();
    private HttpServer payer;
    private String payerUrl;
    /** Released when the test ends, so a stalled response's handler thread stops waiting. */
    private final CountDownLatch done = new CountDownLatch(1);

    @AfterEach
    void stop() throws Exception {
        done.countDown();
        if (payer != null) {
            payer.stop(0);
        }
        if (app != null) {
            app.destroy();
            if (!app.waitFor(30, TimeUnit.SECONDS)) {
                app.destroyForcibly().waitFor();
            }
        }
    }

    @Test
    void manyEmptyCardsFailWithAFindingInsteadOfExhaustingTheHeap() throws Exception {
        long limit = WorkbenchProperties.DEFAULT_MAX_RESPONSE_BYTES;
        int nearByteLimit = (int) ((limit - "{\"cards\":[]}".length() + 1) / 3);
        // The response object, the cards array and the cards are each one JSON value.
        int nearValueLimit = WorkbenchProperties.DEFAULT_MAX_RESPONSE_JSON_VALUES - 2;
        String bytesBody = emptyCards(nearByteLimit);
        assertTrue(bytesBody.length() <= limit && bytesBody.length() > limit - 3, () -> bytesBody.length() + " bytes");
        startPayer(Map.of("bytes", bytesBody, "values", emptyCards(nearValueLimit)));
        String url = startApp();

        for (int i = 0; i < 3; i++) {
            JsonNode run = run(url, "bytes");
            assertEquals("Hook call to crd-order-sign got HTTP 200, but the response holds more than "
                    + WorkbenchProperties.DEFAULT_MAX_RESPONSE_JSON_VALUES + " JSON values, so the workbench did not "
                    + "parse it", step(run, OnboardingRunner.HOOK_REQUEST).path("summary").asText());
            assertEquals("Response holds more than " + WorkbenchProperties.DEFAULT_MAX_RESPONSE_JSON_VALUES
                    + " JSON values", finding(run, OnboardingRunner.RESPONSE_TOO_LARGE_CHECK).path("title").asText());

            run = run(url, "values");
            assertEquals("The hook response has " + nearValueLimit + " cards, more than the "
                    + OnboardingRunner.MAX_CARDS + " the workbench reads one by one",
                    step(run, OnboardingRunner.PARSE_RESPONSE).path("summary").asText());
            assertEquals("FAIL", finding(run, OnboardingRunner.TOO_MANY_CARDS_CHECK).path("severity").asText());
            String schema = finding(run, "response.schema").path("evidence").asText();
            assertTrue(schema.contains("\nand " + (3L * nearValueLimit - 20) + " more\n"), schema);
        }
        HttpResponse<String> healthy = post(url, Map.of("payerId", SyntheticPayers.FABRIKAM_ID,
                "environment", "SANDBOX", "sampleId", "order-sign-hospital-bed"));
        assertEquals(200, healthy.statusCode(), healthy::body);
        assertFalse(log().contains("OutOfMemoryError"), this::log);
    }

    @Test
    void concurrentNearLimitRunsAreBoundedAndAStalledBodyEnds() throws Exception {
        // 999 cards just under 4 MiB, each summary holding a euro sign so Java keeps it as UTF-16: about
        // 30 MiB of heap per run. A reviewer exhausted 512 MiB with 16 of these at once (#162 re-review).
        String nearLimit = euroCards(999, WorkbenchProperties.DEFAULT_MAX_RESPONSE_BYTES);
        startPayer(Map.of("near", nearLimit, "stall", ""));
        String url = startApp("--workbench.request-timeout=3s");
        int concurrent = 16;

        ExecutorService pool = Executors.newFixedThreadPool(concurrent);
        List<HttpResponse<String>> answers = new ArrayList<>();
        try {
            List<Future<HttpResponse<String>>> sent = new ArrayList<>();
            for (int i = 0; i < concurrent; i++) {
                sent.add(pool.submit(() -> post(url, customRun("near"))));
            }
            for (Future<HttpResponse<String>> answer : sent) {
                answers.add(answer.get(5, TimeUnit.MINUTES));
            }
        } finally {
            pool.shutdownNow();
        }
        long ran = answers.stream().filter(a -> a.statusCode() == 200).count();
        long busy = answers.stream().filter(a -> a.statusCode() == 503).count();
        assertEquals(concurrent, ran + busy, () -> answers.stream().map(a -> a.statusCode() + " "
                + a.body().substring(0, Math.min(300, a.body().length()))).toList() + "\n" + log());
        assertTrue(ran >= 1 && busy >= 1, ran + " ran, " + busy + " refused");
        for (HttpResponse<String> answer : answers) {
            if (answer.statusCode() == 503) {
                assertEquals("5", answer.headers().firstValue("Retry-After").orElse(null));
                assertTrue(mapper.readTree(answer.body()).path("detail").asText()
                        .contains("workbench.max-concurrent-runs"), answer::body);
            } else {
                JsonNode run = mapper.readTree(answer.body());
                assertEquals("Parsed 999 cards, 0 system actions and 0 coverage-information entries",
                        step(run, OnboardingRunner.PARSE_RESPONSE).path("summary").asText());
                // Summaries are cut to 1 KiB each, so 100 card views stay far under the body's size.
                assertTrue(answer.body().length() < 256 * 1024,
                        () -> "the run is " + answer.body().length() + " characters");
            }
        }

        // Headers, then a body that never ends: the run fails at the request timeout instead of hanging.
        long start = System.nanoTime();
        HttpResponse<String> stalled = post(url, customRun("stall"));
        long seconds = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start);
        assertEquals(200, stalled.statusCode(), () -> stalled.body() + "\n" + log());
        assertTrue(seconds < 20, seconds + " s");
        JsonNode hook = step(mapper.readTree(stalled.body()), OnboardingRunner.HOOK_REQUEST);
        assertEquals("failed", hook.path("details").path("status").asText(), hook::toString);
        assertTrue(hook.path("summary").asText().contains("got no response"), hook::toString);

        // Every permit came back, so a run sent alone still runs.
        assertEquals(200, post(url, customRun("near")).statusCode());
        assertFalse(log().contains("OutOfMemoryError"), this::log);
    }

    @Test
    void concurrentRunsWithAMillionScopeWordsStayInTheHeap() throws Exception {
        // A token scope of about two million one-letter words just under 4 MiB. Split whole, it made two
        // million strings per run, and 4 runs at once exhausted 512 MiB (#162 re-review 3).
        String head = "{\"access_token\":\"t\",\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"";
        long limit = WorkbenchProperties.DEFAULT_MAX_RESPONSE_BYTES;
        int words = (int) ((limit - head.length() - "a\"}".length()) / 2);
        String token = head + "a ".repeat(words) + "a\"}";
        assertTrue(token.length() <= limit && token.length() > limit - 3, () -> token.length() + " bytes");
        startPayer(Map.of("scope", "{\"cards\":[]}"));
        payer.createContext("/scope/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] answer = token.getBytes(StandardCharsets.US_ASCII);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, answer.length);
            exchange.getResponseBody().write(answer);
            exchange.close();
        });
        String url = startApp();
        Map<String, Object> request = Map.of("sampleId", "order-sign-hospital-bed", "customEndpoint",
                Map.of("baseUrl", payerUrl + "/scope", "authType", "OAUTH2_CLIENT_CREDENTIALS",
                        "clientId", "payer-workbench", "tokenEndpoint", payerUrl + "/scope/token",
                        "credential", "synthetic-secret-" + System.nanoTime(),
                        "igVersion", NorthwindPayer.builder().build().igVersion()));
        int concurrent = 4;

        for (int round = 0; round < 3; round++) {
            ExecutorService pool = Executors.newFixedThreadPool(concurrent);
            try {
                List<Future<HttpResponse<String>>> sent = new ArrayList<>();
                for (int i = 0; i < concurrent; i++) {
                    sent.add(pool.submit(() -> post(url, request)));
                }
                for (Future<HttpResponse<String>> answer : sent) {
                    HttpResponse<String> posted = answer.get(5, TimeUnit.MINUTES);
                    assertEquals(200, posted.statusCode(), () -> posted.body() + "\n" + log());
                    assertTrue(posted.body().length() < 256 * 1024,
                            () -> "the run is " + posted.body().length() + " characters");
                    JsonNode auth = step(mapper.readTree(posted.body()), OnboardingRunner.AUTHENTICATE);
                    assertTrue(auth.path("summary").asText().startsWith("Got a Bearer access token"), auth::toString);
                    String evidence = finding(mapper.readTree(posted.body()), "auth.token").path("evidence").asText();
                    assertTrue(evidence.contains(" and " + (words + 1 - TokenResponseMetadata.MAX_SCOPES)
                            + " more not shown"), evidence);
                }
            } finally {
                pool.shutdownNow();
            }
        }
        assertFalse(log().contains("OutOfMemoryError"), this::log);
    }

    /** {@code count} cards with every field, each padded so the body is just under {@code limit} bytes. */
    private static String euroCards(int count, long limit) {
        String head = "{\"summary\":\"\u20ac";
        String tail = "\",\"indicator\":\"info\",\"source\":{\"label\":\"Synthetic payer\"}}";
        // The euro sign is one character but three bytes.
        long fixed = "{\"cards\":[]}".length() + (count - 1) + (long) count * (head.length() + 2 + tail.length());
        String card = head + "a".repeat((int) ((limit - fixed) / count)) + tail;
        String body = "{\"cards\":[" + String.join(",", java.util.Collections.nCopies(count, card)) + "]}";
        int bytes = body.getBytes(StandardCharsets.UTF_8).length;
        assertTrue(bytes <= limit && bytes > limit - count, () -> bytes + " bytes");
        return body;
    }

    private Map<String, Object> customRun(String path) {
        return Map.of("sampleId", "order-sign-hospital-bed", "customEndpoint",
                Map.of("baseUrl", payerUrl + "/" + path, "authType", "NONE",
                        "igVersion", NorthwindPayer.builder().build().igVersion()));
    }

    private static String emptyCards(int count) {
        return "{\"cards\":[" + "{},".repeat(count - 1) + "{}]}";
    }

    /** Runs the sample against the payer at {@code path}; the run must be answered and stay small. */
    private JsonNode run(String url, String path) throws Exception {
        HttpResponse<String> posted = post(url, customRun(path));
        assertEquals(200, posted.statusCode(), () -> posted.body() + "\n" + log());
        assertTrue(posted.body().length() < 256 * 1024, () -> "the run is " + posted.body().length() + " characters");
        return mapper.readTree(posted.body());
    }

    private static JsonNode step(JsonNode run, String id) {
        return StreamSupport.stream(run.path("steps").spliterator(), false)
                .filter(s -> s.path("stepId").asText().equals(id)).findFirst().orElseThrow();
    }

    private static JsonNode finding(JsonNode run, String checkId) {
        return StreamSupport.stream(run.path("findings").spliterator(), false)
                .filter(f -> f.path("checkId").asText().equals(checkId)).findFirst()
                .orElseThrow(() -> new AssertionError("no " + checkId + " finding in " + run.path("findings")));
    }

    /**
     * No-auth CDS Hooks payers under {@code /<path>} that advertise order-sign and answer each hook call with a
     * body, a second later so runs sent together overlap. The {@code stall} payer sends headers and the start
     * of a body, then nothing more.
     */
    private void startPayer(Map<String, String> hookBodies) throws Exception {
        payer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        payer.setExecutor(Executors.newCachedThreadPool());
        hookBodies.forEach((path, body) -> payer.createContext("/" + path + "/cds-services", exchange -> {
            boolean discovery = exchange.getRequestMethod().equals("GET");
            byte[] answer = (discovery
                    ? "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\",\"prefetch\":{}}]}"
                    : body).getBytes(StandardCharsets.UTF_8);
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            try {
                if (!discovery && path.equals("stall")) {
                    exchange.sendResponseHeaders(200, 0);
                    exchange.getResponseBody().write("{\"cards\":[".getBytes(StandardCharsets.US_ASCII));
                    exchange.getResponseBody().flush();
                    done.await(5, TimeUnit.MINUTES);
                    return;
                }
                if (!discovery) {
                    Thread.sleep(1000);
                }
                exchange.sendResponseHeaders(200, answer.length);
                exchange.getResponseBody().write(answer);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (java.io.IOException e) {
                // The workbench gave up on the response and closed the connection.
            } finally {
                exchange.close();
            }
        }));
        payer.start();
        payerUrl = "http://127.0.0.1:" + payer.getAddress().getPort();
    }

    /**
     * Starts the app from the main classes on this test's class path, with {@link #HEAP} and any extra
     * {@code settings}; returns its base URL.
     */
    private String startApp(String... settings) throws Exception {
        String classPath = Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator))
                .filter(entry -> !entry.replace('\\', '/').endsWith("/test-classes"))
                .reduce((a, b) -> a + File.pathSeparator + b).orElseThrow();
        List<String> command = new ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), HEAP,
                "-Djava.io.tmpdir=" + data, "-cp", classPath, WorkbenchApplication.class.getName(),
                "--spring.config.location=classpath:/application.properties", "--server.address=127.0.0.1",
                "--server.port=0", "--workbench.custom-endpoints.enabled=true",
                "--workbench.audit.journal-dir=" + data.resolve("audit")));
        command.addAll(List.of(settings));
        // Read through a pipe, not a file: on Windows another test's child process can inherit an
        // open log file and keep the temp directory from being deleted.
        app = new ProcessBuilder(command).directory(data.toFile()).redirectErrorStream(true).start();
        Thread reader = new Thread(() -> {
            try (var lines = new java.io.BufferedReader(new java.io.InputStreamReader(app.getInputStream(),
                    StandardCharsets.UTF_8))) {
                for (String line = lines.readLine(); line != null; line = lines.readLine()) {
                    output.append(line).append('\n');
                }
            } catch (java.io.IOException e) {
                // The app was stopped.
            }
        });
        reader.setDaemon(true);
        reader.start();
        for (int i = 0; i < 240; i++) {
            Matcher port = PORT.matcher(log());
            if (port.find()) {
                return "http://127.0.0.1:" + port.group(1);
            }
            assertTrue(app.isAlive(), this::log);
            Thread.sleep(500);
        }
        throw new AssertionError("The app did not start in 120 s:\n" + log());
    }

    private HttpResponse<String> post(String url, Map<String, Object> request) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url + "/api/runs"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(120))
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(request))).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String log() {
        return output.toString();
    }
}
