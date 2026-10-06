package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Report rendering, and that no format leaks a token, client secret or private key planted in a run. */
class RunReportTest {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();
    private static final Instant T0 = Instant.parse("2026-10-01T12:00:00Z");

    private final String token = random(32);
    private final String secret = random(24);
    private final String jwtSignature = random(64);
    private final String pem = generatePem();
    /** A line from the middle of the key body; any part of it in a report is a leak. */
    private final String keyChunk = pem.lines().skip(3).findFirst().orElseThrow();

    @ParameterizedTest
    @EnumSource(ReportRenderer.Format.class)
    void noFormatContainsTheTokenSecretOrKey(ReportRenderer.Format format) {
        String out = ReportRenderer.render(report(leakyRun()), format);
        assertFalse(out.contains(token), format + ": access token leaked");
        assertFalse(out.contains(secret), format + ": client secret leaked");
        assertFalse(out.contains(keyChunk), format + ": private key leaked");
        assertFalse(out.contains(jwtSignature), format + ": JWT signature leaked");
        assertTrue(out.contains("[REDACTED]"), format + ": nothing was marked as redacted");
        assertTrue(out.contains(RunReport.DISCLAIMER_TEXT), format + ": disclaimer missing");
    }

    @ParameterizedTest
    @EnumSource(ReportRenderer.Format.class)
    void everyFormatCoversTheRun(ReportRenderer.Format format) {
        String out = ReportRenderer.render(report(leakyRun()), format);
        for (String expected : List.of("Northwind Health Plan (synthetic)", "northwind-synthetic", "SANDBOX",
                "2.0.1", "2.1.0", "run-1", "FAIL", "Token request rejected", "Rotate the client secret",
                "Resolve connection", "Authenticate", "skipped", "2026-10-01T12:30:00Z", "9.9.9-test")) {
            assertTrue(out.contains(expected), format + " is missing " + expected);
        }
    }

    /** A custom endpoint's credential, planted where a careless step might put it, stays out of every format. */
    @ParameterizedTest
    @EnumSource(ReportRenderer.Format.class)
    void noFormatContainsACustomEndpointCredential(ReportRenderer.Format format) {
        String custom = "PLANTED-CUSTOM-" + random(24);
        String basic = Base64.getEncoder().encodeToString(("payer-workbench:" + custom).getBytes());
        Map<String, Object> exchange = new LinkedHashMap<>();
        exchange.put("method", "POST");
        exchange.put("url", "http://127.0.0.1:18090/oauth/token");
        exchange.put("status", 401);
        exchange.put("requestHeaders", Map.of("Authorization", List.of("Basic " + basic)));
        exchange.put("requestBody", "grant_type=client_credentials&client_secret=" + custom);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("status", "failed");
        details.put("exchanges", List.of(exchange));
        details.put("customEndpoint", Map.of("clientSecret", custom));
        OnboardingRun run = new OnboardingRun("run-custom", "custom-endpoint", Environment.SANDBOX,
                List.of(new StepResult("authenticate", T0, Duration.ofMillis(9), false,
                        "Token request rejected for Authorization: Basic " + basic, details)),
                List.of(new Finding("auth.token", Severity.FAIL, "Token request rejected",
                        "invalid_client for client_secret=" + custom, "Authorization: Basic " + basic
                        + "\n{\"client_secret\":\"" + custom + "\"}", "Check the secret")));
        String out = ReportRenderer.render(report(run), format);
        assertFalse(out.contains(custom), format + ": custom credential leaked");
        assertFalse(out.contains(basic), format + ": Basic credential leaked");
    }

    @Test
    void findingsAreOrderedBySeverityAndCounted() {
        RunReport report = report(leakyRun());
        assertEquals(List.of(Severity.FAIL, Severity.WARN, Severity.PASS),
                report.findings().stream().map(Finding::severity).toList());
        assertEquals(Map.of(Severity.FAIL, 1L, Severity.WARN, 1L, Severity.INFO, 0L, Severity.PASS, 1L), report.counts());
        assertEquals("FAIL", report.verdict().status());
        assertEquals("Authenticate", report.verdict().brokeAt());
    }

    @Test
    void verdictPassesWithWarnings() {
        OnboardingRun run = new OnboardingRun("run-2", "northwind-synthetic", Environment.SANDBOX,
                List.of(new StepResult("discovery", T0, Duration.ofMillis(3), true, "ok", Map.of("status", "passed"))),
                List.of(new Finding("latency", Severity.WARN, "Slow", "Took a while", null, "Speed up")));
        assertEquals("PASS_WITH_WARNINGS", report(run).verdict().status());
    }

    @Test
    void jsonIsParseableAndKeepsAuthorizationScheme() {
        JsonNode json = JsonMapper.builder().build().readTree(ReportRenderer.json(report(leakyRun())));
        assertEquals("run-1", json.path("runId").asString());
        assertEquals("FAIL", json.path("verdict").path("status").asString());
        JsonNode exchange = json.path("steps").get(1).path("details").path("exchanges").get(0);
        assertEquals("Bearer [REDACTED]", exchange.path("requestHeaders").path("Authorization").get(0).asString());
        assertEquals("[REDACTED]", json.path("steps").get(1).path("details").path("access_token").asString());
        assertEquals(6, json.path("steps").size());
    }

    @Test
    void htmlIsSelfContainedAndEscaped() {
        String html = ReportRenderer.html(report(leakyRun()));
        assertTrue(html.startsWith("<!DOCTYPE html>"));
        assertTrue(html.contains("<style>"));
        assertTrue(html.contains("@media print"));
        assertFalse(html.contains("<script"));
        assertFalse(html.contains("<link"));
        assertFalse(html.contains("src="));
        assertTrue(html.contains("&lt;b&gt;"), "markup in a finding must be escaped");
    }

    private RunReport report(OnboardingRun run) {
        return RunReport.of(run, "Northwind Health Plan (synthetic)", "2.1.0", Instant.parse("2026-10-01T12:30:00Z"),
                "9.9.9-test");
    }

    /** A run whose observations carry secrets in every place a careless step or check might put them. */
    private OnboardingRun leakyRun() {
        String jwt = URL.encodeToString("{\"alg\":\"RS384\"}".getBytes()) + "."
                + URL.encodeToString("{\"iss\":\"x\"}".getBytes()) + "." + jwtSignature;
        Map<String, Object> exchange = new LinkedHashMap<>();
        exchange.put("method", "POST");
        exchange.put("url", "http://127.0.0.1:1/token");
        exchange.put("status", 401);
        exchange.put("latencyMs", 7);
        exchange.put("requestHeaders", Map.of("Authorization", List.of("Bearer " + token)));
        exchange.put("requestBody", "grant_type=client_credentials&client_secret=" + secret + "&client_assertion=" + jwt);
        exchange.put("responseHeaders", Map.of("Set-Cookie", List.of("session=" + secret)));
        exchange.put("responseBody", "{\"access_token\":\"" + token + "\",\"note\":\"" + jwt + "\"}");

        Map<String, Object> auth = new LinkedHashMap<>();
        auth.put("status", "failed");
        auth.put("exchanges", List.of(exchange));
        auth.put("access_token", token);
        auth.put("clientSecret", secret);
        auth.put("signingKey", pem);
        auth.put("nested", List.of(Map.of("privateKey", pem, "hint", "client_secret=" + secret)));

        Map<String, Object> connection = Map.of("displayName", "Northwind Health Plan (synthetic)", "igVersion", "2.0.1");
        List<StepResult> steps = List.of(
                new StepResult("resolve-connection", T0, Duration.ofMillis(1), true, "Resolved",
                        Map.of("status", "passed", "connection", connection)),
                new StepResult("authenticate", T0.plusMillis(5), Duration.ofMillis(9), false,
                        "Token request rejected with Bearer " + token, auth),
                new StepResult("discovery", T0, Duration.ZERO, false, "Skipped", Map.of("status", "skipped")),
                new StepResult("hook-request", T0, Duration.ZERO, false, "Skipped", Map.of("status", "skipped")),
                new StepResult("parse-response", T0, Duration.ZERO, false, "Skipped", Map.of("status", "skipped")),
                new StepResult("diagnostics", T0, Duration.ofMillis(2), false, "1 failing check",
                        Map.of("status", "failed")));
        List<Finding> findings = List.of(
                new Finding("discovery.reachable", Severity.PASS, "Discovery reachable", "ok", null, null),
                new Finding("auth.token", Severity.FAIL, "Token request rejected",
                        "The payer said <b>invalid_client</b> for client_secret=" + secret,
                        "Authorization: Bearer " + token + "\n" + pem,
                        "Rotate the client secret; the old one was " + "\"client_secret\":\"" + secret + "\" and " + jwt),
                new Finding("latency", Severity.WARN, "Slow token endpoint", "Took 6 s", null, "Check the payer"));
        return new OnboardingRun("run-1", "northwind-synthetic", Environment.SANDBOX, steps, findings);
    }

    private static String random(int bytes) {
        byte[] b = new byte[bytes];
        new SecureRandom().nextBytes(b);
        return URL.encodeToString(b);
    }

    private static String generatePem() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            String body = Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(gen.generateKeyPair().getPrivate().getEncoded());
            return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
