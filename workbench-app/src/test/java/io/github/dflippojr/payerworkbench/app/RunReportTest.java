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

    @Test
    void htmlLeadsWithTheVerdictIconWordAndBrokeAt() {
        String html = ReportRenderer.html(report(leakyRun()));
        int verdict = html.indexOf("<h2 id=\"verdict-h\">Verdict: Fail</h2>");
        assertTrue(verdict > 0, "verdict word missing");
        assertTrue(html.lastIndexOf("<svg", verdict) > html.indexOf("class=\"vband fail\""), "verdict icon missing");
        assertTrue(html.contains("Broke at <strong>Authenticate</strong>"), "broke-at missing");
        assertTrue(verdict < html.indexOf("<dl class=\"facts\">"), "verdict comes after the facts");
        assertTrue(html.contains("<span class=\"chip fail\">1 fail</span>"));
        String passing = ReportRenderer.html(report(runWith("NONE", hookStep(true,
                exchange("POST", "https://payer.example/cds-services/crd", 200, Map.of(), "{}", "{}")), List.of())));
        assertTrue(passing.contains("<h2 id=\"verdict-h\">Verdict: Pass</h2>"));
        assertFalse(passing.contains("Broke at"));
    }

    @Test
    void htmlTimesAreUtcToTheSecondWithTheFullValueKept() {
        String html = ReportRenderer.html(report(leakyRun()));
        assertTrue(html.contains("<time datetime=\"2026-10-01T12:30:00Z\">2026-10-01 12:30:00 UTC</time>"), html);
        assertTrue(html.contains("<time datetime=\"2026-10-01T12:00:00Z\">2026-10-01 12:00:00 UTC</time>"));
        assertEquals("<time datetime=\"2026-10-01T12:00:00.123456789Z\">2026-10-01 12:00:00 UTC</time>",
                ReportRenderer.utc("2026-10-01T12:00:00.123456789Z"));
        assertEquals("—", ReportRenderer.utc(null));
        assertEquals("not a time", ReportRenderer.utc("not a time"));
        assertTrue(ReportRenderer.json(report(leakyRun())).contains("\"2026-10-01T12:30:00Z\""), "JSON keeps ISO");
    }

    @Test
    void htmlFailingCallPutsCurlBeforeTheRequestAndResponseSideBySide() {
        String html = ReportRenderer.html(report(leakyRun()));
        int curl = html.indexOf("Reproduce with curl");
        int two = html.indexOf("<div class=\"two\">");
        assertTrue(curl > html.indexOf("Failing call") && curl < two, "curl is not first");
        assertTrue(two < html.indexOf("Request headers") && html.indexOf("Request body") < html.indexOf("Response headers"));
        assertTrue(html.contains("<span class=\"chip fail\">HTTP 401</span><span class=\"ms\">7 ms</span>"));
    }

    @Test
    void htmlDarkModeIsScreenOnlyAndPrintKeepsHeadingsWithTheirBlock() {
        String html = ReportRenderer.html(report(leakyRun()));
        assertTrue(html.contains("@media screen and (prefers-color-scheme:dark)"));
        assertFalse(html.contains("@media (prefers-color-scheme"), "dark mode would reach print");
        String print = html.substring(html.indexOf("@media print"));
        assertTrue(print.contains("h2,h3,.label,.fhead,.call-line{break-after:avoid}"));
        assertTrue(print.contains("pre,.finding,.curl{break-inside:auto}"));
        assertFalse(html.contains("border-left"), "no card relies on a coloured left border");
    }

    @Test
    void everyHtmlStatusHasAWordBesideItsIcon() {
        String html = ReportRenderer.html(report(leakyRun()));
        for (String chip : List.of("<span class=\"chip pass\">passed</span>", "<span class=\"chip fail\">failed</span>",
                "<span class=\"chip skip\">skipped</span>")) {
            assertTrue(html.contains(chip), chip);
        }
        for (String word : List.of("Fail", "Warn", "Pass")) {
            assertTrue(html.contains("aria-hidden=\"true\">") && html.contains("</svg>" + word + "</span><h3>"), word);
        }
    }

    @Test
    void everyHtmlHeadingIsClosedOnItsOwnLine() {
        String html = ReportRenderer.html(report(leakyRun()));
        for (String line : html.split("\n")) {
            for (int level = 1; level <= 4; level++) {
                if (line.contains("<h" + level)) {
                    assertTrue(line.contains("</h" + level + ">"), "unclosed heading: " + line);
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = ReportRenderer.Format.class, names = {"MD", "HTML"})
    void failingCallSitsBetweenTheVerdictTableAndTheTimeline(ReportRenderer.Format format) {
        String out = ReportRenderer.render(report(leakyRun()), format);
        int section = out.indexOf("Failing call");
        assertTrue(section > out.indexOf("Workbench version"), format + ": section is before the verdict table");
        assertTrue(section < out.indexOf("Step timeline"), format + ": section is after the timeline");
        for (String expected : List.of("Authenticate", "POST http://127.0.0.1:1/token", "HTTP 401 · 7 ms",
                "Authorization: Bearer [REDACTED]", "Content-Type: application/x-www-form-urlencoded",
                "WWW-Authenticate: Bearer error=", "grant_type=client_credentials&client_secret=[REDACTED]",
                "Reproduce with curl", "request-body.txt")) {
            assertTrue(out.contains(format == ReportRenderer.Format.HTML ? ReportRenderer.esc(expected) : expected),
                    format + " is missing " + expected);
        }
    }

    @Test
    void jsonReportHasNoFailingCallSection() {
        String json = ReportRenderer.json(report(leakyRun()));
        assertFalse(json.contains("Failing call"));
        assertFalse(json.contains("curl"));
    }

    @Test
    void curlCarriesPlaceholdersAndNoCredential() {
        FailingCall call = FailingCall.of(report(leakyRun())).orElseThrow();
        String curl = call.curl();
        assertTrue(curl.startsWith("curl -X POST 'http://127.0.0.1:1/token'"), curl);
        assertTrue(curl.contains("-H 'Authorization: Bearer <ACCESS_TOKEN>'"), curl);
        assertTrue(curl.contains("-H 'Content-Type: application/x-www-form-urlencoded'"), curl);
        assertTrue(curl.contains("-H 'X-Debug-Assertion: "), curl);
        assertTrue(curl.endsWith("--data-binary @request-body.txt"), curl);
        for (String absent : List.of("[REDACTED]", "Cookie", "X-Api-Key", "Content-Length", "Host:", token, secret,
                jwtSignature, keyChunk, "-----BEGIN")) {
            assertFalse(curl.contains(absent), "curl contains " + absent + ": " + curl);
        }
        for (ReportRenderer.Format format : List.of(ReportRenderer.Format.MD, ReportRenderer.Format.HTML)) {
            String out = ReportRenderer.render(report(leakyRun()), format);
            assertTrue(out.contains(format == ReportRenderer.Format.HTML ? ReportRenderer.esc(curl) : curl),
                    format::toString);
        }
    }

    @Test
    void cdsHooksJwtGetsAClientJwtPlaceholderAndJsonBodiesArePrettyPrinted() {
        Map<String, Object> exchange = exchange("POST", "https://payer.example/cds-services/crd-order-sign", 401,
                Map.of("Authorization", List.of("Bearer " + token), "Content-Type", List.of("application/json")),
                "{\"hook\":\"order-sign\",\"prefetch\":{\"patient\":{\"resourceType\":\"Patient\"}}}",
                "{\"error\":\"invalid_token\"}");
        OnboardingRun run = runWith("CDS_HOOKS_JWT", hookStep(false, exchange), List.of());
        FailingCall call = FailingCall.of(report(run)).orElseThrow();
        assertEquals("Send sample hook request", call.stepTitle());
        assertTrue(call.curl().contains("-H 'Authorization: Bearer <CLIENT_JWT>'"), call.curl());
        assertTrue(call.curl().endsWith("--data-binary @request.json"), call.curl());
        assertTrue(call.requestBody().json());
        assertTrue(call.requestBody().text().contains("\"prefetch\" : {"), call.requestBody().text());
        String md = ReportRenderer.markdown(report(run));
        assertTrue(md.contains("```json\n{\n  \"hook\" : \"order-sign\""), md);
        assertFalse(md.contains(token));
    }

    @Test
    void completedRunWithAFailingCheckShowsTheHookRequest() {
        Map<String, Object> exchange = exchange("POST", "https://payer.example/cds-services/crd", 200,
                Map.of("Authorization", List.of("Bearer " + token)), "{}", "{\"cards\":[]}");
        OnboardingRun run = runWith("OAUTH2_CLIENT_CREDENTIALS", hookStep(true, exchange),
                List.of(new Finding("perf.latency", Severity.FAIL, "Slow", "Took 9 s", null, "Speed up")));
        RunReport report = report(run);
        assertEquals("FAIL", report.verdict().status());
        assertEquals(null, report.verdict().brokeAt());
        assertEquals("HTTP 200", FailingCall.of(report).orElseThrow().status());
        assertTrue(ReportRenderer.html(report).contains("<section class=\"failing-call\""));
    }

    @Test
    void noSectionWithoutAFailureOrWithoutAnExchange() {
        Map<String, Object> exchange = exchange("POST", "https://payer.example/cds-services/crd", 200, Map.of(), "{}", "{}");
        OnboardingRun healthy = runWith("NONE", hookStep(true, exchange), List.of());
        assertEquals("PASS", report(healthy).verdict().status());
        OnboardingRun resolveFailed = new OnboardingRun("run-r", "northwind-synthetic", Environment.PRODUCTION,
                List.of(new StepResult("resolve-connection", T0, Duration.ofMillis(1), false, "No record",
                                Map.of("status", "failed")),
                        new StepResult("hook-request", T0, Duration.ZERO, false, "Skipped", Map.of("status", "skipped"))),
                List.of(new Finding("connection.record", Severity.FAIL, "No record", "none", null, "Add one")));
        for (OnboardingRun run : List.of(healthy, resolveFailed)) {
            assertTrue(FailingCall.of(report(run)).isEmpty());
            assertFalse(ReportRenderer.markdown(report(run)).contains("Failing call"));
            assertFalse(ReportRenderer.html(report(run)).contains("Failing call"));
        }
    }

    @Test
    void bodiesOverSixteenKibAreTruncatedInMarkdownAndHtmlOnly() {
        String tail = "END-OF-BODY-" + random(8);
        String big = "x".repeat(FailingCall.BODY_LIMIT_BYTES) + tail;
        Map<String, Object> exchange = exchange("POST", "https://payer.example/cds-services/crd", 500,
                Map.of(), big, "é".repeat(FailingCall.BODY_LIMIT_BYTES));
        RunReport report = report(runWith("NONE", hookStep(false, exchange), List.of()));
        FailingCall call = FailingCall.of(report).orElseThrow();
        assertTrue(call.requestBody().truncated());
        assertEquals(FailingCall.BODY_LIMIT_BYTES, call.requestBody().text().length());
        assertTrue(call.responseBody().truncated());
        assertEquals(FailingCall.BODY_LIMIT_BYTES / 2, call.responseBody().text().length(), "two bytes per é");
        for (ReportRenderer.Format format : List.of(ReportRenderer.Format.MD, ReportRenderer.Format.HTML)) {
            String out = ReportRenderer.render(report, format);
            assertTrue(out.contains(FailingCall.TRUNCATED_NOTE), format::toString);
            assertFalse(out.contains(tail), format + " has the full body");
        }
        assertTrue(ReportRenderer.json(report).contains(tail), "JSON lost the full body");
        assertFalse(ReportRenderer.json(report).contains(FailingCall.TRUNCATED_NOTE));
    }

    /** A credential hidden behind a JSON escape is unescaped by pretty-printing, then redacted again. */
    @Test
    void prettyPrintingCannotRevealAnEscapedCredential() {
        String body = "{\"hint\":\"Bearer\\u0020" + token + "\",\"pem\":\"-----BEGIN PRIVATE KEY\\u002D----\\n"
                + keyChunk + "\\n-----END PRIVATE KEY-----\"}";
        Map<String, Object> exchange = exchange("POST", "https://payer.example/cds-services/crd", 400,
                Map.of("Content-Type", List.of("application/json")), body, body);
        RunReport report = report(runWith("NONE", hookStep(false, exchange), List.of()));
        for (ReportRenderer.Format format : List.of(ReportRenderer.Format.MD, ReportRenderer.Format.HTML)) {
            String out = ReportRenderer.render(report, format);
            assertFalse(out.contains(token), format + ": escaped token leaked");
            assertFalse(out.contains(keyChunk), format + ": escaped key leaked");
        }
    }

    @Test
    void curlQuotesValuesForTheShell() {
        Map<String, Object> exchange = exchange("GET", "https://payer.example/cds-services?q=it's", 500,
                Map.of("X-Note", List.of("it's $(id) `x`")), null, null);
        FailingCall call = FailingCall.of(report(runWith("NONE", hookStep(false, exchange), List.of()))).orElseThrow();
        assertEquals("curl -X GET 'https://payer.example/cds-services?q=it'\\''s' \\\n  -H 'X-Note: it'\\''s $(id) `x`'",
                call.curl());
        assertEquals(null, call.bodyFile());
    }

    private static Map<String, Object> exchange(String method, String url, int status, Map<String, List<String>> headers,
                                                String requestBody, String responseBody) {
        Map<String, Object> exchange = new LinkedHashMap<>();
        exchange.put("method", method);
        exchange.put("url", url);
        exchange.put("status", status);
        exchange.put("latencyMs", 12);
        exchange.put("requestHeaders", headers);
        exchange.put("requestBody", requestBody);
        exchange.put("responseHeaders", Map.of());
        exchange.put("responseBody", responseBody);
        return exchange;
    }

    private static StepResult hookStep(boolean ok, Map<String, Object> exchange) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("status", ok ? "passed" : "failed");
        details.put("exchanges", List.of(exchange));
        return new StepResult("hook-request", T0, Duration.ofMillis(12), ok, ok ? "ok" : "Rejected", details);
    }

    private static OnboardingRun runWith(String authType, StepResult hook, List<Finding> findings) {
        Map<String, Object> connection = Map.of("displayName", "Synthetic", "igVersion", "2.0.1", "authType", authType);
        return new OnboardingRun("run-x", "northwind-synthetic", Environment.SANDBOX,
                List.of(new StepResult("resolve-connection", T0, Duration.ofMillis(1), true, "Resolved",
                        Map.of("status", "passed", "connection", connection)), hook), findings);
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
        Map<String, List<String>> requestHeaders = new LinkedHashMap<>();
        requestHeaders.put("Authorization", List.of("Bearer " + token));
        requestHeaders.put("Content-Type", List.of("application/x-www-form-urlencoded"));
        requestHeaders.put("Content-Length", List.of("512"));
        requestHeaders.put("Host", List.of("127.0.0.1:1"));
        requestHeaders.put("Cookie", List.of("session=" + secret));
        requestHeaders.put("X-Api-Key", List.of(secret));
        requestHeaders.put("X-Debug-Assertion", List.of(jwt));
        exchange.put("requestHeaders", requestHeaders);
        exchange.put("requestBody", "grant_type=client_credentials&client_secret=" + secret + "&client_assertion=" + jwt
                + "\n" + pem);
        Map<String, List<String>> responseHeaders = new LinkedHashMap<>();
        responseHeaders.put("Set-Cookie", List.of("session=" + secret));
        responseHeaders.put("WWW-Authenticate", List.of("Bearer error=\"invalid_token\", token=\"" + jwt + "\""));
        exchange.put("responseHeaders", responseHeaders);
        exchange.put("responseBody", "{\"access_token\":\"" + token + "\",\"note\":\"" + jwt + "\",\"client_secret\":\""
                + secret + "\",\"key\":\"" + pem.replace("\n", "\\n") + "\"}");

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
