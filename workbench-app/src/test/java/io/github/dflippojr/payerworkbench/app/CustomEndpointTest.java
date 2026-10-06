package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.mock.FabrikamPayer;
import io.github.dflippojr.payerworkbench.mock.NorthwindPayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
