package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
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
        // Delegate the per-run store to an inspectable real instance, without changing production ownership.
        InMemoryCredentials store = new InMemoryCredentials();
        try (var construction = mockConstruction(InMemoryCredentials.class,
                withSettings().defaultAnswer(delegatesTo(store)))) {
            runner.run(new RunRequest(null, Environment.SANDBOX, SAMPLE, List.of(), null, null,
                    new RunRequest.CustomEndpoint(payer.baseUrl(), AuthType.OAUTH2_PRIVATE_KEY_JWT,
                            "custom-client", tokenBase + "/oauth/token", "custom-smart-key", payer.igVersion(), pem)));
            assertEquals(1, construction.constructed().size());
            verify(construction.constructed().getFirst()).put(anyString(), anyString());
            verify(construction.constructed().getFirst()).remove("custom-endpoint-credential");
            assertTrue(store.resolve("custom-endpoint-credential").isEmpty());
        }
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
        // Northwind wants a token, so the hook fails, but the run itself is accepted and reported.
        assertTrue(run.steps().get(0).ok());
        assertFalse(run.steps().stream().allMatch(s -> s.ok()));
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
    void refusesDestinationsThatAreNotPublicHttpsOrLoopback() {
        for (String url : List.of(
                "http://example.com/r4",              // plain http to a non-loopback host
                "http://169.254.169.254/latest",      // cloud metadata
                "https://169.254.169.254/latest",
                "https://10.0.0.5/r4",                // private
                "https://192.168.1.10/r4",
                "https://172.16.0.1/r4",
                "https://100.100.100.200/r4",         // carrier-grade NAT (Alibaba metadata)
                "https://[fd00:ec2::254]/r4",         // unique-local, AWS IPv6 metadata
                "https://[fe80::1]/r4",               // link-local
                "https://2130706433/r4",              // 127.0.0.1 written as one number
                "https://metadata.google.internal/",
                "https://user:pw@example.com/r4",     // credentials in the URL
                "https://example.com/r4?token=x",
                "ftp://example.com/",
                "file:///etc/passwd")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> runner.run(custom(url, AuthType.NONE, null, null, null)), url);
            assertFalse(e.getMessage().isBlank(), url);
        }
    }

    @Test
    void rejectionMessagesSayWhy() {
        assertTrue(message("http://example.com/r4").contains("Plain http is only allowed to loopback"));
        assertTrue(message("https://10.0.0.5/r4").contains("private, loopback, link-local or metadata"));
        assertTrue(message("https://169.254.169.254/").contains("169.254.169.254"));
    }

    @Test
    void tokenEndpointIsCheckedToo() throws Exception {
        NorthwindPayer payer = northwind("s");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> runner.run(custom(
                payer.baseUrl(), AuthType.OAUTH2_CLIENT_CREDENTIALS, "https://10.0.0.5/oauth/token", null, "s")));
        assertTrue(e.getMessage().startsWith("Token endpoint"), e.getMessage());
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
    void apiAnswersBadEndpointsWith400() throws Exception {
        HttpResponse<String> response = send("POST", "/api/runs", """
                {"sampleId":"order-sign-hospital-bed","customEndpoint":{"baseUrl":"https://10.0.0.5/r4","authType":"NONE"}}""");
        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("private, loopback, link-local or metadata"), response.body());
        assertTrue(mapper.readTree(send("GET", "/api/features", null).body()).path("customEndpoints").asBoolean());
    }

    private String message(String url) {
        return assertThrows(IllegalArgumentException.class,
                () -> runner.run(custom(url, AuthType.NONE, null, null, null))).getMessage();
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
