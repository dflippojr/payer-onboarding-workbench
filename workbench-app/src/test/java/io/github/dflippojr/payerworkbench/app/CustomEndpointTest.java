package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import io.github.dflippojr.payerworkbench.mock.TailspinPayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

/**
 * Runs the onboarding flow against a second in-process payer registered as a custom
 * endpoint (a loopback mock; no real payer is ever called), and checks the guard rails:
 * it matches the built-in payer, bad destinations are refused, and the credential never
 * reaches a run, report, log or actuator endpoint.
 */
@ExtendWith(OutputCaptureExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.custom-endpoints.enabled=true")
class CustomEndpointTest {

    private static final String SAMPLE = "order-sign-hospital-bed";
    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    @Value("${local.server.port}")
    int port;

    @Autowired
    OnboardingRunner runner;

    @Autowired
    RunStore runs;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newHttpClient();
    private final List<AutoCloseable> open = new ArrayList<>();

    @AfterEach
    void close() throws Exception {
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    @Test
    void customNorthwindMatchesTheBuiltInPayer() throws Exception {
        String secret = secret();
        NorthwindPayer payer = northwind(secret);
        OnboardingRun custom = runner.run(custom(payer.baseUrl(), AuthType.OAUTH2_CLIENT_CREDENTIALS,
                payer.tokenEndpoint(), null, secret));
        OnboardingRun builtIn = runner.run(new RunRequest(SyntheticPayers.NORTHWIND_ID, Environment.SANDBOX, SAMPLE,
                List.of(), null, null));

        assertEquals(RunRequest.CUSTOM_PAYER_ID, custom.payerId());
        assertEquals(checks(builtIn), checks(custom));
        assertTrue(custom.steps().stream().allMatch(s -> s.ok()), "every step passes: " + custom.steps());
    }

    @Test
    void connectionEditsApplyToCustomEndpointsForOneRun() throws Exception {
        String secret = secret();
        NorthwindPayer payer = NorthwindPayer.builder().client("edited-client", secret).build().start(0);
        open.add(payer);
        var endpoint = new RunRequest.CustomEndpoint(payer.baseUrl(), AuthType.OAUTH2_CLIENT_CREDENTIALS,
                "original-client", payer.tokenEndpoint(), null, "1.0.0", secret);
        var edits = new RunRequest.ConnectionOverrides("/", payer.igVersion(), "edited-client");
        var posted = send("POST", "/api/runs", mapper.writeValueAsString(
                new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, edits, endpoint)));
        assertEquals(200, posted.statusCode());
        var run = mapper.readTree(posted.body());
        run.path("steps").forEach(step -> assertTrue(step.path("ok").asBoolean(), step.toString()));
        var resolved = run.path("steps").get(0).path("details");
        assertEquals(payer.baseUrl() + "/", resolved.path("connection").path("baseUrl").asText());
        assertEquals(payer.igVersion(), resolved.path("connection").path("igVersion").asText());
        assertEquals("edited-client", resolved.path("connection").path("clientId").asText());
        assertEquals(mapper.valueToTree(Map.of("baseUrl", payer.baseUrl() + "/",
                "igVersion", payer.igVersion(), "clientId", "edited-client")), resolved.path("edited"));

        var unedited = runner.run(new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null, endpoint));
        var original = mapper.valueToTree(unedited.steps().getFirst().details()).path("connection");
        assertEquals(payer.baseUrl(), original.path("baseUrl").asText());
        assertEquals("1.0.0", original.path("igVersion").asText());
        assertEquals("original-client", original.path("clientId").asText());
        assertEquals(Map.of(), unedited.steps().getFirst().details().get("edited"));
    }

    @Test
    void customFabrikamSignsAClientJwtWithTheSuppliedKey() throws Exception {
        KeyPair key = rsa();
        JwksServer jwks = new JwksServer(Map.of("custom-key-1", key.getPublic()));
        open.add(jwks::close);
        FabrikamPayer payer = FabrikamPayer.builder().client("custom-client", jwks.url()).build();
        payer.start(0);
        open.add(payer);
        String pem = PemKeys.toPem("PRIVATE KEY", key.getPrivate().getEncoded());

        OnboardingRun run = runner.run(new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null,
                new RunRequest.CustomEndpoint(payer.baseUrl(), AuthType.CDS_HOOKS_JWT, "custom-client", null,
                        "custom-key-1", payer.igVersion(), pem)));

        assertTrue(run.steps().stream().allMatch(s -> s.ok()), run.steps().toString());
        assertFalse(run.toString().contains(pem.lines().skip(3).findFirst().orElseThrow()));
    }

    @ParameterizedTest
    @CsvSource({"RSA,false", "EC,false", "RSA,true", "EC,true"})
    void customSmartAuthenticatesAndRedactsEverySurface(String algorithm, boolean rejected,
                                                       CapturedOutput output) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("EC")) {
            generator.initialize(new ECGenParameterSpec("secp384r1"));
        } else {
            generator.initialize(2048);
        }
        KeyPair key = generator.generateKeyPair();
        String pem = PemKeys.toPem("PRIVATE KEY", key.getPrivate().getEncoded());
        String chunk = pem.lines().skip(3).findFirst().orElseThrow();
        JwksServer jwks = new JwksServer(Map.of("custom-smart-key", key.getPublic()));
        open.add(jwks::close);

        // A local token relay captures the actual SDK assertion in test memory only.
        HttpServer token = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String tokenBase = "http://127.0.0.1:" + token.getAddress().getPort();
        TailspinPayer payer = TailspinPayer.builder().client("custom-client", jwks.url())
                .publicBaseUrl(tokenBase).build().start(0);
        open.add(payer);
        open.add(() -> token.stop(0));
        if (rejected) payer.faults().enable(Fault.WRONG_AUDIENCE_REJECT);
        AtomicReference<String> assertion = new AtomicReference<>();
        AtomicReference<String> correlation = new AtomicReference<>();
        token.createContext("/oauth/token", exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            for (String part : form.split("&")) {
                if (part.startsWith("client_assertion=")) {
                    assertion.set(URLDecoder.decode(part.substring("client_assertion=".length()), StandardCharsets.UTF_8));
                }
            }
            correlation.set(exchange.getRequestHeaders().getFirst(RequestIdClient.HEADER));
            try {
                HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(payer.tokenEndpoint()))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
                byte[] bytes = response.body().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(response.statusCode(), bytes.length);
                exchange.getResponseBody().write(bytes);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new java.io.IOException("Local token relay interrupted", e);
            } finally {
                exchange.close();
            }
        });
        token.start();
        Map<String, String> endpoint = Map.of("baseUrl", payer.baseUrl(), "authType", "OAUTH2_PRIVATE_KEY_JWT",
                "clientId", "custom-client", "tokenEndpoint", tokenBase + "/oauth/token", "keyId", "custom-smart-key",
                "igVersion", payer.igVersion(), "credential", pem);
        String body = mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", endpoint));
        HttpResponse<String> posted = send("POST", "/api/runs", body);
        assertEquals(200, posted.statusCode(), "custom SMART request accepted");
        var run = mapper.readTree(posted.body());
        assertEquals("custom-endpoint", run.path("payerId").asText());
        String runId = run.path("runId").asText();
        assertEquals(runId, correlation.get());
        var finding = java.util.stream.StreamSupport.stream(run.path("findings").spliterator(), false)
                .filter(f -> f.path("checkId").asText().equals("auth.client-assertion")).findFirst().orElseThrow();
        assertEquals(rejected ? "FAIL" : "PASS", finding.path("severity").asText());
        if (rejected) {
            assertTrue(finding.path("evidence").asText().contains(TailspinPayer.WRONG_AUDIENCE));
            assertTrue(finding.path("evidence").asText().contains(tokenBase + "/oauth/token"));
            assertEquals("failed", run.path("steps").get(2).path("details").path("status").asText());
            assertEquals("skipped", run.path("steps").get(3).path("details").path("status").asText());
        } else {
            run.path("steps").forEach(step -> assertTrue(step.path("ok").asBoolean(), "SMART step passes"));
        }
        assertTrue(assertion.get() != null, "SDK sent a signed assertion");
        String[] parts = assertion.get().split("\\.");
        assertEquals(algorithm.equals("RSA") ? "RS384" : "ES384",
                mapper.readTree(Base64.getUrlDecoder().decode(parts[0])).path("alg").asText());
        String signature = parts[2];
        List<String> surfaces = new ArrayList<>(List.of(posted.body(), send("GET", "/api/runs/" + runId, null).body()));
        for (String format : List.of("md", "html", "json")) {
            var report = send("GET", "/api/runs/" + runId + "/report?format=" + format, null);
            assertEquals(200, report.statusCode());
            surfaces.add(report.body());
        }
        for (String actuator : List.of("health", "info", "prometheus")) {
            surfaces.add(send("GET", "/actuator/" + actuator, null).body());
        }
        surfaces.add(output.getAll());
        for (String surface : surfaces) {
            assertFalse(surface.contains(chunk), "private key chunk leaked");
            assertFalse(surface.contains(assertion.get()), "signed assertion leaked");
            assertFalse(surface.contains(signature), "signature leaked");
            assertFalse(surface.contains("client_assertion="), "token request body leaked");
        }
    }

    @Test
    void customCredentialIsRemovedAfterTheRun() throws Exception {
        KeyPair key = rsa();
        String pem = PemKeys.toPem("PRIVATE KEY", key.getPrivate().getEncoded());
        JwksServer jwks = new JwksServer(Map.of("custom-smart-key", key.getPublic()));
        open.add(jwks::close);
        TailspinPayer payer = TailspinPayer.builder().client("custom-client", jwks.url()).build().start(0);
        open.add(payer);
        // Delegate the per-run store to an inspectable real instance, without changing production ownership.
        InMemoryCredentials store = new InMemoryCredentials();
        try (var construction = mockConstruction(InMemoryCredentials.class,
                withSettings().defaultAnswer(delegatesTo(store)))) {
            runner.run(new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null,
                    new RunRequest.CustomEndpoint(payer.baseUrl(), AuthType.OAUTH2_PRIVATE_KEY_JWT,
                            "custom-client", payer.tokenEndpoint(), "custom-smart-key", payer.igVersion(), pem)));
            assertEquals(1, construction.constructed().size());
            verify(construction.constructed().getFirst()).put(anyString(), anyString());
            verify(construction.constructed().getFirst()).remove("custom-endpoint-credential");
            assertTrue(store.resolve("custom-endpoint-credential").isEmpty());
        }
    }

    @Test
    void smartMissingInputsAndBadDestinationsReturnSafe400() throws Exception {
        Map<String, String> complete = Map.of("baseUrl", "http://127.0.0.1:9", "authType", "OAUTH2_PRIVATE_KEY_JWT",
                "clientId", "custom-client", "tokenEndpoint", "http://127.0.0.1:9/oauth/token",
                "keyId", "custom-key", "credential", "PLANTED-MALFORMED-PEM");
        for (String field : List.of("clientId", "tokenEndpoint", "keyId", "credential")) {
            var endpoint = new java.util.LinkedHashMap<>(complete);
            endpoint.remove(field);
            var response = send("POST", "/api/runs", mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", endpoint)));
            assertEquals(400, response.statusCode());
            assertTrue(mapper.readTree(response.body()).path("detail").isTextual(), "structured validation message");
            assertFalse(response.body().contains("PLANTED-MALFORMED-PEM"));
        }
        for (String field : List.of("baseUrl", "tokenEndpoint")) {
            var endpoint = new java.util.LinkedHashMap<>(complete);
            endpoint.put(field, "https://169.254.169.254/latest");
            var response = send("POST", "/api/runs", mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", endpoint)));
            assertEquals(400, response.statusCode());
            assertTrue(mapper.readTree(response.body()).path("detail").isTextual(), "structured validation message");
            assertFalse(response.body().contains("PLANTED-MALFORMED-PEM"));
        }
        assertTrue(mapper.readTree(send("GET", "/api/features", null).body()).path("customEndpoints").asBoolean());
    }

    @Test
    void malformedSmartPemIsASafeFailedRun(CapturedOutput output) throws Exception {
        NorthwindPayer payer = northwind("s");
        String planted = "PLANTED-MALFORMED-PRIVATE-KEY";
        var response = send("POST", "/api/runs", mapper.writeValueAsString(Map.of("sampleId", SAMPLE,
                "customEndpoint", Map.of("baseUrl", payer.baseUrl(), "authType", "OAUTH2_PRIVATE_KEY_JWT",
                        "clientId", "custom-client", "tokenEndpoint", payer.tokenEndpoint(), "keyId", "custom-key",
                        "credential", planted))));
        assertEquals(200, response.statusCode());
        assertEquals("failed", mapper.readTree(response.body()).path("steps").get(2).path("details").path("status").asText());
        assertFalse(response.body().contains(planted));
        assertFalse(output.getAll().contains(planted));
    }

    @Test
    void noAuthEndpointIsAcceptedAndReported() throws Exception {
        NorthwindPayer payer = northwind("s");
        OnboardingRun run = runner.run(custom(payer.baseUrl(), AuthType.NONE, null, null, null));
        // Northwind wants a token, so the hook call is rejected; Authenticate has nothing to do and passes.
        assertEquals(Map.of(OnboardingRunner.RESOLVE, "passed", OnboardingRunner.DISCOVERY, "passed",
                OnboardingRunner.AUTHENTICATE, "passed", OnboardingRunner.HOOK_REQUEST, "failed",
                OnboardingRunner.PARSE_RESPONSE, "skipped", OnboardingRunner.DIAGNOSTICS, "failed"), statuses(run));
        RunVerdict verdict = RunVerdict.of(run);
        assertEquals("FAIL", verdict.status());
        assertEquals(OnboardingRunner.HOOK_REQUEST, verdict.brokeAt());
        var rejected = run.findings().stream().filter(f -> f.checkId().equals("auth.hook-rejected")).toList();
        assertEquals(1, rejected.size(), run.findings().toString());
        assertTrue(rejected.getFirst().explanation().contains("carried no credentials"), rejected.toString());
    }

    @Test
    void longListsShowTheFirstEntriesAndCountTheRest() throws Exception {
        // Under the JSON value limit, 150 services and 150 cards still make 100 views each (#162).
        StringBuilder services = new StringBuilder("{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\"}");
        for (int i = 1; i < 150; i++) {
            services.append(",{\"hook\":\"patient-view\",\"id\":\"pv-").append(i).append("\"}");
        }
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        server.createContext("/long/cds-services", exchange -> {
            exchange.getRequestBody().readAllBytes();
            respond(exchange, exchange.getRequestMethod().equals("GET") ? services + "]}"
                    : "{\"cards\":[" + "{},".repeat(149) + "{}]}");
        });
        server.start();

        OnboardingRun run = runner.run(custom("http://127.0.0.1:" + server.getAddress().getPort() + "/long",
                AuthType.NONE, null, null, null));

        StepResult discovery = run.steps().get(1);
        assertEquals("Found 150 services; order-sign is served by crd-order-sign", discovery.summary());
        assertEquals(OnboardingRunner.MAX_VIEWS, ((List<?>) discovery.details().get("services")).size());
        assertEquals(50, discovery.details().get("servicesNotShown"));
        StepResult parse = run.steps().get(4);
        assertEquals("Parsed 150 cards, but card 1 lacks summary, indicator, source.label; card 2 lacks summary, "
                + "indicator, source.label; card 3 lacks summary, indicator, source.label; card 4 lacks summary, "
                + "indicator, source.label; card 5 lacks summary, indicator, source.label; and 145 more cards lack "
                + "fields", parse.summary());
        assertEquals(OnboardingRunner.MAX_VIEWS, ((List<?>) parse.details().get("cards")).size());
        assertEquals(50, parse.details().get("cardsNotShown"));
        assertTrue(run.findings().stream().noneMatch(f -> f.checkId().equals(OnboardingRunner.TOO_MANY_CARDS_CHECK)));
    }

    @Test
    void longPayerStringsAreCutSoOneResponseMakesASmallRun() throws Exception {
        // A few huge strings stay under both response limits, but must not make a run of megabytes (#162).
        String keys = java.util.stream.IntStream.range(0, 50)
                .mapToObj(i -> "\"key" + i + "-" + "k".repeat(10_000) + "\":\"Patient/{{context.patientId}}\"")
                .collect(java.util.stream.Collectors.joining(","));
        String services = "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"crd-order-sign\",\"prefetch\":{"
                + keys + "}},{\"hook\":\"" + "h".repeat(500_000) + "\",\"id\":\"" + "i".repeat(500_000) + "\"}]}";
        String card = "{\"summary\":\"" + "s".repeat(400_000) + "\",\"indicator\":\"" + "w".repeat(20_000)
                + "\",\"source\":{\"label\":\"" + "l".repeat(20_000) + "\"}}";
        String cards = "{\"cards\":[" + String.join(",", java.util.Collections.nCopies(8, card)) + "]}";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        server.createContext("/huge/cds-services", exchange -> {
            exchange.getRequestBody().readAllBytes();
            respond(exchange, exchange.getRequestMethod().equals("GET") ? services : cards);
        });
        server.start();

        OnboardingRun run = runner.run(custom("http://127.0.0.1:" + server.getAddress().getPort() + "/huge",
                AuthType.NONE, null, null, null));

        String cut = "s".repeat(io.github.dflippojr.payerworkbench.core.TextLimit.MAX_CHARS) + "\u2026";
        List<?> views = (List<?>) run.steps().get(4).details().get("cards");
        assertEquals(8, views.size());
        assertEquals(cut, ((Map<?, ?>) views.getFirst()).get("summary"));
        Map<?, ?> selected = (Map<?, ?>) ((List<?>) run.steps().get(1).details().get("services")).get(0);
        assertEquals(OnboardingRunner.MAX_LIST_ENTRIES, ((List<?>) selected.get("prefetchKeys")).size());
        assertEquals(30, selected.get("prefetchKeysNotShown"));
        Map<?, ?> other = (Map<?, ?>) ((List<?>) run.steps().get(1).details().get("services")).get(1);
        assertEquals(io.github.dflippojr.payerworkbench.core.TextLimit.MAX_CHARS + 1, ((String) other.get("id")).length());
        assertEquals(io.github.dflippojr.payerworkbench.core.TextLimit.MAX_CHARS + 1, ((String) other.get("hook")).length());
        runs.save(run);
        long size = RunStore.sizeOf(runs.find(run.runId()).orElseThrow());
        assertTrue(size < 256 * 1024, "the stored run is " + size + " bytes");

        // The token step's strings too: a huge token_type, a scope of a million words, and a huge error.
        String token = "{\"access_token\":\"t\",\"expires_in\":300,\"token_type\":\"Bearer" + "x".repeat(1_000_000)
                + "\",\"scope\":\"system/*.read " + "a ".repeat(1_000_000) + "\"}";
        String error = "{\"error\":\"" + "e".repeat(1_000_000) + "\",\"error_description\":\""
                + "d".repeat(1_000_000) + "\"}";
        server.createContext("/huge/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            respond(exchange, token);
        });
        server.createContext("/huge/token-error", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] bytes = error.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(400, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/huge";
        for (String endpoint : List.of(base + "/token", base + "/token-error")) {
            OnboardingRun oauth = runner.run(custom(base, AuthType.OAUTH2_CLIENT_CREDENTIALS, endpoint, null, secret()));
            StepResult auth = oauth.steps().get(2);
            assertTrue(auth.summary().length() < 4 * io.github.dflippojr.payerworkbench.core.TextLimit.MAX_CHARS,
                    () -> auth.summary().length() + " characters");
            runs.save(oauth);
            long oauthSize = RunStore.sizeOf(runs.find(oauth.runId()).orElseThrow());
            // Discovery, token and hook exchanges keep a 64 Ki body each; uncut, this run was 8.5 MB.
            assertTrue(oauthSize < 512 * 1024, endpoint + ": the stored run is " + oauthSize + " bytes");
        }
        OnboardingRun granted = runner.run(custom(base, AuthType.OAUTH2_CLIENT_CREDENTIALS, base + "/token", null,
                secret()));
        assertTrue(granted.steps().get(2).ok(), granted.steps().get(2).summary());
        Map<?, ?> tokenView = (Map<?, ?>) granted.steps().get(2).details().get("token");
        assertEquals("Bearer" + "x".repeat(io.github.dflippojr.payerworkbench.core.TextLimit.MAX_CHARS - 6) + "…",
                tokenView.get("tokenType"));
        String evidence = granted.findings().stream().filter(f -> f.checkId().equals("auth.token")).findFirst()
                .orElseThrow().evidence();
        assertTrue(evidence.contains(", scope=system/*.read" + " a".repeat(TokenResponseMetadata.MAX_SCOPES - 1)
                + " and " + (1_000_000 - TokenResponseMetadata.MAX_SCOPES + 1) + " more not shown"), evidence);
    }

    @Test
    void aServiceIdTooLongForAUrlFailsDiscovery() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        server.createContext("/long-id/cds-services", exchange -> {
            exchange.getRequestBody().readAllBytes();
            respond(exchange, "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"" + "a".repeat(5000) + "\"}]}");
        });
        server.start();

        OnboardingRun run = runner.run(custom("http://127.0.0.1:" + server.getAddress().getPort() + "/long-id",
                AuthType.NONE, null, null, null));

        StepResult discovery = run.steps().get(1);
        assertFalse(discovery.ok());
        assertEquals("The payer advertises a service id of 5000 characters for order-sign, longer than the 1024 "
                + "the workbench puts in a URL", discovery.summary());
        assertEquals("skipped", run.steps().get(2).details().get("status"));
    }

    @Test
    void healthyNoAuthEndpointPasses() throws Exception {
        // A CDS Hooks server that serves discovery and one hook without asking for credentials.
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        AtomicReference<String> authorization = new AtomicReference<>("not called");
        server.createContext("/ok/cds-services", exchange -> {
            String body;
            if (exchange.getRequestMethod().equals("GET") && exchange.getRequestURI().getPath().equals("/ok/cds-services")) {
                body = """
                        {"services":[{"hook":"order-sign","id":"crd-order-sign","prefetch":{}}]}""";
            } else if (exchange.getRequestMethod().equals("POST")
                    && exchange.getRequestURI().getPath().equals("/ok/cds-services/crd-order-sign")) {
                exchange.getRequestBody().readAllBytes();
                authorization.set(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
                body = """
                        {"cards":[{"summary":"s","indicator":"info","source":{"label":"l"}}]}""";
            } else {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        OnboardingRun run = runner.run(custom("http://127.0.0.1:" + server.getAddress().getPort() + "/ok",
                AuthType.NONE, null, null, null));

        assertEquals("null", authorization.get(), "the hook call carries no Authorization header");
        assertTrue(run.steps().stream().allMatch(s -> s.ok()), "every step passes: " + run.steps());
        assertEquals("No authentication configured; the hook call is sent without credentials",
                run.steps().get(2).summary());
        assertEquals("NONE", run.steps().get(2).details().get("authType"));
        assertEquals("PASS", RunVerdict.of(run).status(), run.findings().toString());
    }

    @Test
    void smartJwtAccessTokenIsNotMistakenForTheClientAssertion(CapturedOutput output) throws Exception {
        // Most real SMART servers issue a JWT access token; the hook call then carries it as Bearer.
        long now = System.currentTimeMillis() / 1000;
        String accessToken = URL.encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8))
                + "." + URL.encodeToString(("{\"iss\":\"https://auth.payer.example\",\"sub\":\"some-user\","
                + "\"aud\":\"https://api.payer.example\",\"exp\":" + (now + 3600) + ",\"iat\":" + now + "}")
                .getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        AtomicReference<String> authorization = new AtomicReference<>("not called");
        server.createContext("/ok/oauth/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            respond(exchange, "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"Bearer\",\"expires_in\":300}");
        });
        server.createContext("/ok/cds-services", exchange -> {
            if (exchange.getRequestMethod().equals("GET")) {
                respond(exchange, """
                        {"services":[{"hook":"order-sign","id":"crd-order-sign","prefetch":{}}]}""");
            } else {
                exchange.getRequestBody().readAllBytes();
                authorization.set(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
                respond(exchange, """
                        {"cards":[{"summary":"s","indicator":"info","source":{"label":"l"}}]}""");
            }
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/ok";
        String body = mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", Map.of(
                "baseUrl", base, "authType", "OAUTH2_PRIVATE_KEY_JWT", "clientId", "my-client",
                "tokenEndpoint", base + "/oauth/token", "keyId", "k1", "igVersion", igVersion,
                "credential", PemKeys.toPem("PRIVATE KEY", rsa().getPrivate().getEncoded()))));

        HttpResponse<String> posted = send("POST", "/api/runs", body);

        assertEquals(200, posted.statusCode(), posted.body());
        assertEquals("Bearer " + accessToken, authorization.get(), "the hook call carried the JWT access token");
        var run = mapper.readTree(posted.body());
        run.path("steps").forEach(step -> assertTrue(step.path("ok").asBoolean(), "SMART step passes: " + step));
        var claims = run.path("steps").get(2).path("details").path("clientAssertionClaims");
        assertEquals("my-client", claims.path("iss").asText(), claims.toString());
        assertEquals("my-client", claims.path("sub").asText(), claims.toString());
        var finding = java.util.stream.StreamSupport.stream(run.path("findings").spliterator(), false)
                .filter(f -> f.path("checkId").asText().equals("auth.client-assertion")).findFirst().orElseThrow();
        assertEquals("PASS", finding.path("severity").asText(), finding.toString());
        String runId = run.path("runId").asText();
        List<String> surfaces = new ArrayList<>(List.of(posted.body(), send("GET", "/api/runs/" + runId, null).body()));
        for (String format : List.of("md", "html", "json")) {
            surfaces.add(send("GET", "/api/runs/" + runId + "/report?format=" + format, null).body());
        }
        surfaces.add(output.getAll());
        for (String surface : surfaces) {
            assertFalse(surface.contains("auth.payer.example"), "access-token claims leaked");
            assertFalse(surface.contains("some-user"), "access-token claims leaked");
            assertFalse(surface.contains(accessToken.split("\\.")[1]), "access token leaked");
        }
    }

    @Test
    void payerEchoedCredentialsAreMaskedOnEverySurface() throws Exception {
        // A debug server that echoes credentials into a 401 body: a Basic pair that is all letters in
        // base64 ("user:pass"), a colon-split bearer token, numeric secrets and a private_key field.
        String base = startEchoServer(401, """
                {"error":"unauthorized","access_token":918273645,"echo":{"private_key":"MIIEvSyntheticOnly123"},\
                "debug":"Authorization: Basic dXNlcjpwYXNz\\nBearer abc123:SECRETPART\\n{\\"client_secret\\":918273646}"}""");
        String body = mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint",
                Map.of("baseUrl", base, "authType", "NONE", "igVersion", igVersion)));

        HttpResponse<String> posted = send("POST", "/api/runs", body);

        assertEquals(200, posted.statusCode(), posted.body());
        var run = mapper.readTree(posted.body());
        assertEquals("Hook call to crd-order-sign returned HTTP 401", run.path("steps").get(3).path("summary").asText());
        String recorded = run.path("steps").get(3).path("details").path("exchanges").get(0).path("responseBody").asText();
        assertTrue(recorded.contains("Basic [REDACTED]") && recorded.contains("\"access_token\":\"[REDACTED]\""), recorded);
        String runId = run.path("runId").asText();
        List<String> surfaces = new ArrayList<>(List.of(posted.body(), send("GET", "/api/runs/" + runId, null).body()));
        for (String format : List.of("md", "html", "json")) {
            HttpResponse<String> report = send("GET", "/api/runs/" + runId + "/report?format=" + format, null);
            assertEquals(200, report.statusCode());
            surfaces.add(report.body());
        }
        for (String surface : surfaces) {
            for (String secret : List.of("dXNlcjpwYXNz", "SECRETPART", "918273645", "918273646", "MIIEvSyntheticOnly123")) {
                assertFalse(surface.contains(secret), secret + " leaked");
            }
        }
    }

    @Test
    void aRunPastTheConcurrencyLimitIsRefusedWith503() throws Exception {
        // Every permitted custom run waits in its hook call, so one more is refused instead of queued.
        int limit = WorkbenchProperties.DEFAULT_MAX_CONCURRENT_RUNS;
        CountDownLatch inHook = new CountDownLatch(limit);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService payerThreads = Executors.newCachedThreadPool();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(payerThreads);
        open.add(payerThreads::shutdownNow);
        open.add(() -> server.stop(0));
        server.createContext("/held/cds-services", exchange -> {
            if (exchange.getRequestMethod().equals("GET")) {
                respond(exchange, """
                        {"services":[{"hook":"order-sign","id":"crd-order-sign","prefetch":{}}]}""");
                return;
            }
            exchange.getRequestBody().readAllBytes();
            inHook.countDown();
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            respond(exchange, "{\"cards\":[]}");
        });
        server.start();
        String run = mapper.writeValueAsString(Map.of("sampleId", SAMPLE, "customEndpoint", Map.of("baseUrl",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/held", "authType", "NONE", "igVersion", igVersion)));
        ExecutorService callers = Executors.newFixedThreadPool(limit);
        try {
            List<Future<HttpResponse<String>>> held = new ArrayList<>();
            for (int i = 0; i < limit; i++) {
                held.add(callers.submit(() -> send("POST", "/api/runs", run)));
            }
            assertTrue(inHook.await(30, TimeUnit.SECONDS), "every permitted run reached its hook call");

            HttpResponse<String> refused = send("POST", "/api/runs", run);

            assertEquals(503, refused.statusCode(), refused.body());
            assertEquals("5", refused.headers().firstValue("Retry-After").orElse(null));
            assertEquals(limit + " custom-endpoint runs are already in progress (workbench.max-concurrent-runs); "
                    + "try again when one finishes", mapper.readTree(refused.body()).path("detail").asText());
            release.countDown();
            for (Future<HttpResponse<String>> answer : held) {
                assertEquals(200, answer.get(30, TimeUnit.SECONDS).statusCode());
            }
            assertEquals(200, send("POST", "/api/runs", run).statusCode(), "the finished runs gave their permits back");
        } finally {
            release.countDown();
            callers.shutdownNow();
        }
    }

    @Test
    void secretCutInsideAnEscapeByTheJsonValueLimitIsMaskedOnEverySurface() throws Exception {
        // The kept 8 Ki prefix of a body with too many JSON values ends in the first half of an escaped
        // backslash inside an echoed access token.
        String start = "{\"access_token\":\"FAKE-CREDENTIAL-123456";
        String hookBody = start + "x".repeat(ResponseTooLargeException.JSON_VALUES_PREFIX_CHARS - 1 - start.length())
                + "\\\\\",\"cards\":[" + "{},".repeat(100_000) + "{}]}";
        String base = startEchoServer(200, hookBody);

        HttpResponse<String> posted = send("POST", "/api/runs", mapper.writeValueAsString(Map.of("sampleId", SAMPLE,
                "customEndpoint", Map.of("baseUrl", base, "authType", "NONE", "igVersion", igVersion))));

        assertEquals(200, posted.statusCode(), posted.body());
        var run = mapper.readTree(posted.body());
        String recorded = run.path("steps").get(3).path("details").path("exchanges").get(0).path("responseBody").asText();
        assertEquals("{\"access_token\":\"[REDACTED]\"\n[not parsed: more than "
                + WorkbenchProperties.DEFAULT_MAX_RESPONSE_JSON_VALUES + " JSON values; kept the first "
                + ResponseTooLargeException.JSON_VALUES_PREFIX_CHARS + " characters]", recorded);
        String runId = run.path("runId").asText();
        List<String> surfaces = new ArrayList<>(List.of(posted.body(), send("GET", "/api/runs/" + runId, null).body()));
        for (String format : List.of("md", "html", "json")) {
            HttpResponse<String> report = send("GET", "/api/runs/" + runId + "/report?format=" + format, null);
            assertEquals(200, report.statusCode());
            surfaces.add(report.body());
        }
        for (String surface : surfaces) {
            assertFalse(surface.contains("FAKE-CREDENTIAL"), "the access token leaked");
        }
    }

    @Test
    void oversizedHookBodyIsCutAtTheLimitAndNamed() throws Exception {
        long limit = WorkbenchProperties.DEFAULT_MAX_RESPONSE_BYTES;
        long recordedLength = limit + 1 + "[truncated at 4194304 bytes]".length();
        String note = "\n[kept the first " + ExchangeView.BODY_LIMIT_CHARS + " of " + recordedLength + " characters]";
        // 64 MiB, streamed in chunks so the test payer never holds it in memory either.
        String base = startEchoServer(200, null);

        for (int i = 0; i < 3; i++) {
            HttpResponse<String> posted = send("POST", "/api/runs", mapper.writeValueAsString(Map.of("sampleId", SAMPLE,
                    "customEndpoint", Map.of("baseUrl", base, "authType", "NONE", "igVersion", igVersion))));

            assertEquals(200, posted.statusCode());
            assertTrue(posted.body().length() < 2 * limit, "POST response is " + posted.body().length() + " chars");
            var run = mapper.readTree(posted.body());
            var hook = run.path("steps").get(3);
            assertFalse(hook.path("ok").asBoolean());
            assertEquals("Hook call to crd-order-sign got HTTP 200, but the response exceeded the 4 MiB limit, "
                    + "so the workbench stopped reading it", hook.path("summary").asText());
            var exchange = hook.path("details").path("exchanges").get(0);
            assertEquals(200, exchange.path("status").asInt(), exchange.toString().substring(0, 300));
            String recorded = exchange.path("responseBody").asText();
            assertTrue(recorded.startsWith("{\"cards\":[],\"padding\":\"aaaa"), recorded.substring(0, 40));
            // The run keeps a prefix of what was read, so max-runs such runs stay small (#162).
            assertTrue(recorded.endsWith(note), recorded.substring(recorded.length() - 60));
            assertEquals(ExchangeView.BODY_LIMIT_CHARS + note.length(), recorded.length());
            assertTrue(RunStore.sizeOf(runs.find(run.path("runId").asText()).orElseThrow()) < 2 * ExchangeView.BODY_LIMIT_CHARS);
            assertTrue(exchange.path("transportError").asText().contains("exceeded the 4 MiB limit"),
                    exchange.path("transportError").asText());
            var finding = java.util.stream.StreamSupport.stream(run.path("findings").spliterator(), false)
                    .filter(f -> f.path("checkId").asText().equals(OnboardingRunner.RESPONSE_TOO_LARGE_CHECK))
                    .findFirst().orElseThrow();
            assertEquals("FAIL", finding.path("severity").asText());
            assertTrue(finding.path("title").asText().contains("4 MiB"), finding.toString());
            assertFalse(posted.body().contains("OutOfMemoryError"));
            assertFalse(posted.body().contains("got no response"));
        }
        OnboardingRun healthy = runner.run(new RunRequest(SyntheticPayers.FABRIKAM_ID, Environment.SANDBOX, SAMPLE,
                List.of(), null, null));
        assertTrue(healthy.steps().stream().allMatch(s -> s.ok()), "every step passes: " + healthy.steps());
        assertTrue(healthy.findings().stream().noneMatch(f -> f.severity() == io.github.dflippojr.payerworkbench.core.Severity.FAIL),
                healthy.findings()::toString);
    }

    /**
     * A no-auth CDS Hooks server whose hook call answers {@code status} with {@code hookBody}, or
     * with a 64 MiB body when {@code hookBody} is null. Returns its base URL.
     */
    private String startEchoServer(int status, String hookBody) throws java.io.IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        server.createContext("/echo/cds-services", exchange -> {
            if (exchange.getRequestMethod().equals("GET")) {
                respond(exchange, """
                        {"services":[{"hook":"order-sign","id":"crd-order-sign","prefetch":{}}]}""");
                return;
            }
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            if (hookBody != null) {
                byte[] bytes = hookBody.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }
            byte[] chunk = "a".repeat(64 * 1024).getBytes(StandardCharsets.US_ASCII);
            exchange.sendResponseHeaders(status, 0);
            try (var out = exchange.getResponseBody()) {
                out.write("{\"cards\":[],\"padding\":\"".getBytes(StandardCharsets.US_ASCII));
                for (int i = 0; i < 1024; i++) {
                    out.write(chunk);
                }
                out.write("\"}".getBytes(StandardCharsets.US_ASCII));
            } catch (java.io.IOException e) {
                // The workbench stopped reading at its limit and closed the connection.
            } finally {
                exchange.close();
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/echo";
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static Map<String, Object> statuses(OnboardingRun run) {
        Map<String, Object> statuses = new java.util.LinkedHashMap<>();
        run.steps().forEach(step -> statuses.put(step.stepId(), RunVerdict.stepStatus(step)));
        return statuses;
    }

    /** A payer-advertised service id that is not URL-safe fails at discovery, with a finding that names it. */
    @Test
    void unusableServiceIdFailsAtDiscoveryWithAFinding() throws Exception {
        HttpServer fake = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        fake.createContext("/space/cds-services", exchange -> {
            byte[] bytes = "{\"services\":[{\"hook\":\"order-sign\",\"id\":\"order sign\",\"prefetch\":{}}]}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        fake.start();
        open.add(() -> fake.stop(0));

        OnboardingRun run = runner.run(custom("http://127.0.0.1:" + fake.getAddress().getPort() + "/space",
                AuthType.NONE, null, null, null));

        var failed = run.steps().stream().filter(s -> !s.ok() && !s.stepId().equals("diagnostics")
                && !"skipped".equals(s.details().get("status"))).toList();
        assertEquals(List.of("discovery"), failed.stream().map(s -> s.stepId()).toList());
        assertTrue(failed.getFirst().summary().contains("'order sign'"), failed.getFirst()::summary);
        assertFalse(failed.getFirst().summary().contains("Unexpected error"), failed.getFirst()::summary);
        assertEquals("skipped", run.steps().get(2).details().get("status"));
        var finding = run.findings().stream().filter(f -> f.checkId().equals("discovery.services")
                && f.severity() == io.github.dflippojr.payerworkbench.core.Severity.FAIL).findFirst().orElseThrow();
        assertTrue(finding.evidence().contains("order sign"), finding::evidence);
        assertFalse(run.steps().getLast().ok(), "diagnostics must not pass a broken run");
    }

    @Test
    void plantedCredentialNeverLeaves(CapturedOutput output) throws Exception {
        String secret = "PLANTED-" + secret();
        NorthwindPayer payer = northwind(secret);
        String body = mapper.writeValueAsString(Map.of(
                "sampleId", SAMPLE,
                "customEndpoint", Map.of("baseUrl", payer.baseUrl(), "authType", "OAUTH2_CLIENT_CREDENTIALS",
                        "clientId", "payer-workbench", "tokenEndpoint", payer.tokenEndpoint(), "credential", secret)));
        HttpResponse<String> posted = send("POST", "/api/runs", body);
        assertEquals(200, posted.statusCode(), posted.body());
        String runId = mapper.readTree(posted.body()).path("runId").asText();

        List<String> surfaces = new ArrayList<>(List.of(posted.body(), send("GET", "/api/runs/" + runId, null).body(),
                send("GET", "/api/payers", null).body()));
        for (String format : List.of("md", "html", "json")) {
            HttpResponse<String> report = send("GET", "/api/runs/" + runId + "/report?format=" + format, null);
            assertEquals(200, report.statusCode());
            surfaces.add(report.body());
        }
        for (String actuator : List.of("health", "info", "prometheus")) {
            surfaces.add(send("GET", "/actuator/" + actuator, null).body());
        }
        String basic = Base64.getEncoder().encodeToString(("payer-workbench:" + secret).getBytes());
        for (String surface : surfaces) {
            assertFalse(surface.contains(secret), "credential leaked");
            assertFalse(surface.contains(basic), "Basic credential leaked");
        }
        assertFalse(output.getAll().contains(secret), "credential in the log");
        assertFalse(output.getAll().contains(basic), "Basic credential in the log");
        assertFalse(new RunRequest.CustomEndpoint("http://127.0.0.1:1", AuthType.NONE, null, null, null, null, secret)
                .toString().contains(secret));
    }

    @Test
    void rejectsIncompleteCredentialsAndFaults() {
        String base = "http://127.0.0.1:9";
        assertThrows(IllegalArgumentException.class, () -> runner.run(custom(base, AuthType.OAUTH2_CLIENT_CREDENTIALS,
                base + "/token", null, null)));
        assertThrows(IllegalArgumentException.class, () -> runner.run(custom(base, AuthType.CDS_HOOKS_JWT,
                null, null, "pem")));
        assertThrows(IllegalArgumentException.class, () -> runner.run(custom(base, AuthType.NONE, null, null, "unused")));
        assertThrows(IllegalArgumentException.class, () -> runner.run(custom(base, AuthType.OAUTH2_PRIVATE_KEY_JWT,
                null, null, "x")));
        assertThrows(IllegalArgumentException.class, () -> runner.run(new RunRequest(null, Environment.SANDBOX, SAMPLE,
                List.of("discovery-500"), null, null, new RunRequest.CustomEndpoint(base, AuthType.NONE, null, null,
                null, null, null))));
    }

    @Test
    void suffixCannotAddAQueryFragmentOrUserInfo() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        open.add(() -> server.stop(0));
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/", exchange -> {
            calls.incrementAndGet();
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/ok";
        for (String suffix : List.of("?x=1#", "#", "/r4?x", "@127.0.0.1:1", "/user@host",
                "/r4#fragment", "/bad\\path", "/two words", "/control\npath")) {
            RunRequest request = new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null,
                    new RunRequest.ConnectionOverrides(suffix, null, null),
                    new RunRequest.CustomEndpoint(base, AuthType.NONE, null, null, null, null, null));
            var response = send("POST", "/api/runs", mapper.writeValueAsString(request));
            assertEquals(400, response.statusCode(), suffix);
            assertTrue(mapper.readTree(response.body()).path("detail").asText()
                    .startsWith("baseUrlSuffix may only add path segments"), response.body());
        }
        assertEquals(0, calls.get(), "invalid edits are refused before any payer call");
    }

    private static final String igVersion = NorthwindPayer.builder().build().igVersion();

    private static RunRequest custom(String baseUrl, AuthType auth, String tokenEndpoint, String keyId, String credential) {
        return new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null,
                new RunRequest.CustomEndpoint(baseUrl, auth, auth == AuthType.NONE ? null : "payer-workbench",
                        tokenEndpoint, keyId, igVersion, credential));
    }

    private static List<String> checks(OnboardingRun run) {
        // tls.handshake only has something to say over https, and loopback http has no handshake.
        return run.findings().stream().filter(f -> !f.checkId().equals("tls.handshake"))
                .map(f -> f.severity() + " " + f.checkId()).sorted().toList();
    }

    private NorthwindPayer northwind(String secret) throws java.io.IOException {
        NorthwindPayer payer = NorthwindPayer.builder().client("payer-workbench", secret).build();
        payer.start(0);
        open.add(payer);
        return payer;
    }

    private HttpResponse<String> send(String method, String path, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Content-Type", "application/json");
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String secret() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return URL.encodeToString(bytes);
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
