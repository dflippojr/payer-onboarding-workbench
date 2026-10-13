package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.payerworkbench.core.Redactor;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The HTTP call a failing report shows in full, with a {@code curl} command that reproduces it. Built only from
 * {@link RunReport.Step#details()}, which {@link RunReport} has already redacted, and every string is passed
 * through {@link Redactor} once more after formatting, so a JSON escape that hid a credential from the first pass
 * cannot reveal it here. The curl command carries placeholders, never a credential or its redacted form.
 *
 * @param stepTitle       the step the call belongs to
 * @param method          HTTP method
 * @param url             request URL
 * @param status          {@code HTTP 401} or {@code no response}
 * @param latencyMs       latency, or {@code null} if not recorded
 * @param requestHeaders  one {@code Name: value} line per header value
 * @param requestBody     the request body, or {@code null} if none was sent
 * @param responseHeaders one {@code Name: value} line per header value
 * @param responseBody    the response body, or {@code null} if none arrived
 * @param transportError  why no response arrived, or {@code null}
 * @param curl            the reproduction command
 * @param bodyFile        the file name the curl command reads the request body from, or {@code null}
 */
record FailingCall(
        String stepTitle,
        String method,
        String url,
        String status,
        Long latencyMs,
        List<String> requestHeaders,
        Body requestBody,
        List<String> responseHeaders,
        Body responseBody,
        String transportError,
        String curl,
        String bodyFile
) {

    /** Largest body, in UTF-8 bytes, shown in the HTML and Markdown reports. */
    static final int BODY_LIMIT_BYTES = 16 * 1024;

    static final String TRUNCATED_NOTE = "Truncated; the JSON report has the full body.";

    static final String ACCESS_TOKEN = "<ACCESS_TOKEN>";
    static final String CLIENT_JWT = "<CLIENT_JWT>";
    static final String BASIC_CREDENTIALS = "<BASE64_CLIENT_ID_AND_SECRET>";
    static final String SECRET = "<SECRET>";

    /** Headers curl sets itself or that would only carry a credential. */
    private static final Set<String> CURL_DROPPED = Set.of("content-length", "host");
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9!#$%&'*+.^_`|~-]+");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** A body as shown: pretty-printed if it is JSON, cut at {@link #BODY_LIMIT_BYTES}. */
    record Body(String text, boolean json, boolean truncated) {
    }

    /**
     * The call to show for a {@code FAIL} report: the last exchange of the step the flow broke at, else the last
     * exchange of the hook request (the flow completed but a check failed, or it broke at a step that makes no
     * call, such as parsing the response).
     */
    static Optional<FailingCall> of(RunReport report) {
        if (!"FAIL".equals(report.verdict().status())) {
            return Optional.empty();
        }
        Optional<RunReport.Step> brokeAt = report.steps().stream()
                .filter(s -> !s.stepId().equals(OnboardingRunner.DIAGNOSTICS) && "failed".equals(s.status()))
                .findFirst();
        Optional<RunReport.Step> hook = report.steps().stream()
                .filter(s -> s.stepId().equals(OnboardingRunner.HOOK_REQUEST))
                .findFirst();
        for (Optional<RunReport.Step> candidate : List.of(brokeAt, hook)) {
            Optional<FailingCall> call = candidate.flatMap(step -> lastExchange(step)
                    .map(e -> build(step.title(), e, authType(report))));
            if (call.isPresent()) {
                return call;
            }
        }
        return Optional.empty();
    }

    private static Optional<Map<?, ?>> lastExchange(RunReport.Step step) {
        if (step.details().get("exchanges") instanceof List<?> list && !list.isEmpty()
                && list.getLast() instanceof Map<?, ?> e) {
            return Optional.of(e);
        }
        return Optional.empty();
    }

    private static String authType(RunReport report) {
        return report.steps().stream()
                .filter(s -> s.stepId().equals(OnboardingRunner.RESOLVE))
                .findFirst()
                .map(s -> s.details().get("connection"))
                .filter(Map.class::isInstance)
                .map(c -> ((Map<?, ?>) c).get("authType"))
                .map(String::valueOf)
                .orElse(null);
    }

    private static FailingCall build(String stepTitle, Map<?, ?> e, String authType) {
        String method = text(e.get("method"));
        String url = text(e.get("url"));
        Object status = e.get("status");
        boolean responded = status instanceof Number n && n.intValue() > 0;
        Long latency = e.get("latencyMs") instanceof Number n ? n.longValue() : null;
        Map<?, ?> requestHeaders = e.get("requestHeaders") instanceof Map<?, ?> m ? m : Map.of();
        Map<?, ?> responseHeaders = e.get("responseHeaders") instanceof Map<?, ?> m ? m : Map.of();
        Body requestBody = body(e.get("requestBody"));
        String bodyFile = requestBody == null ? null : requestBody.json() ? "request.json" : "request-body.txt";
        return new FailingCall(stepTitle, method, url, responded ? "HTTP " + status : "no response", latency,
                headerLines(requestHeaders), requestBody, headerLines(responseHeaders), body(e.get("responseBody")),
                e.get("transportError") == null ? null : text(e.get("transportError")),
                curl(method, url, requestHeaders, bodyFile, authType), bodyFile);
    }

    private static List<String> headerLines(Map<?, ?> headers) {
        List<String> lines = new ArrayList<>();
        headers.forEach((name, values) -> {
            for (Object value : values instanceof List<?> list ? list : List.of(String.valueOf(values))) {
                lines.add(text(name) + ": " + text(value));
            }
        });
        return List.copyOf(lines);
    }

    static Body body(Object raw) {
        if (raw == null || String.valueOf(raw).isEmpty()) {
            return null;
        }
        String text = String.valueOf(raw);
        String pretty = prettyJson(text);
        String shown = Redactor.redact(pretty == null ? text : pretty);
        byte[] bytes = shown.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= BODY_LIMIT_BYTES) {
            return new Body(shown, pretty != null, false);
        }
        return new Body(cut(shown, BODY_LIMIT_BYTES), pretty != null, true);
    }

    private static String prettyJson(String text) {
        String trimmed = text.strip();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
            return null;
        }
        try {
            JsonNode node = JSON.readTree(trimmed);
            // The default printer ends lines with the platform separator.
            return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(node).replace("\r\n", "\n");
        } catch (JacksonException notJson) {
            return null;
        }
    }

    /** The longest prefix of {@code text} that fits in {@code limit} UTF-8 bytes, never splitting a character. */
    private static String cut(String text, int limit) {
        int bytes = 0;
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            int size = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
            if (bytes + size > limit) {
                break;
            }
            bytes += size;
            i += Character.charCount(cp);
        }
        return text.substring(0, i);
    }

    /**
     * {@code curl} for the call: non-secret request headers as sent, an {@code Authorization} header with a
     * placeholder in place of the credential, and the request body from a file. Any value the redactor touched is
     * replaced by a placeholder, so neither a credential nor its redacted form reaches the command.
     */
    static String curl(String method, String url, Map<?, ?> headers, String bodyFile, String authType) {
        List<String> parts = new ArrayList<>();
        parts.add("curl -X " + (TOKEN.matcher(method).matches() ? method : quote(method)) + " " + quote(placeholders(url)));
        headers.forEach((rawName, values) -> {
            String name = text(rawName);
            String lower = name.toLowerCase(Locale.ROOT);
            if (CURL_DROPPED.contains(lower) || !TOKEN.matcher(name).matches()) {
                return;
            }
            List<?> list = values instanceof List<?> l ? l : List.of(String.valueOf(values));
            if (lower.equals("authorization")) {
                if (!list.isEmpty()) {
                    parts.add("-H " + quote("Authorization: " + authorization(text(list.getFirst()), authType)));
                }
                return;
            }
            if (Redactor.isSensitiveHeader(name)) {
                return;
            }
            for (Object value : list) {
                parts.add("-H " + quote(name + ": " + placeholders(text(value))));
            }
        });
        if (bodyFile != null) {
            parts.add("--data-binary @" + bodyFile);
        }
        return String.join(" \\\n  ", parts);
    }

    /** The scheme that was sent, with a placeholder for its credential. */
    private static String authorization(String sent, String authType) {
        String scheme = sent.strip().split("\\s+", 2)[0];
        if (scheme.equalsIgnoreCase("Basic")) {
            return "Basic " + BASIC_CREDENTIALS;
        }
        if (scheme.equalsIgnoreCase("Bearer") || !TOKEN.matcher(scheme).matches()) {
            return "Bearer " + (AuthType.CDS_HOOKS_JWT.name().equals(authType) ? CLIENT_JWT : ACCESS_TOKEN);
        }
        return scheme + " " + SECRET;
    }

    /** Redacts once more and swaps every redaction mark for a placeholder. */
    private static String placeholders(String value) {
        return Redactor.redact(value).replace(Redactor.MASK, SECRET);
    }

    /** POSIX shell single quotes. */
    private static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String text(Object value) {
        return value == null ? "" : Redactor.redact(String.valueOf(value)).replace("\r", "").replace("\n", " ");
    }
}
