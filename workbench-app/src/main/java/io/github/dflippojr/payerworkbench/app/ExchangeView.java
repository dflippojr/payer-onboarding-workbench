package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.Redactor;

import java.util.List;
import java.util.Map;

/**
 * An {@link HttpExchange} as the UI shows it, with latency in milliseconds. The
 * headers and bodies are the exchange's, which were redacted when it was built.
 * Each body keeps at most its first {@link #BODY_LIMIT_CHARS} characters, so a run
 * that {@link RunStore} remembers stays small even when a payer sent a body near
 * {@code workbench.max-response-bytes}; the diagnostics read the whole body before that.
 */
public record ExchangeView(
        String method,
        String url,
        int status,
        long latencyMs,
        Map<String, List<String>> requestHeaders,
        String requestBody,
        Map<String, List<String>> responseHeaders,
        String responseBody,
        String transportError
) {
    /** Most characters of each body a run keeps: 64 Ki, more than the reports show. */
    static final int BODY_LIMIT_CHARS = 64 * 1024;

    static ExchangeView of(HttpExchange e) {
        return new ExchangeView(e.method(), e.url(), e.status(), e.latency().toMillis(), e.requestHeaders(),
                kept(e.requestBody()), e.responseHeaders(), kept(e.responseBody()), e.transportError());
    }

    /**
     * The body's first {@link #BODY_LIMIT_CHARS} characters and a note, or the body if it is no longer.
     * The prefix is redacted again, so a mask the cut went through ({@code "[REDAC}) is whole again.
     */
    static String kept(String body) {
        if (body == null || body.length() <= BODY_LIMIT_CHARS) {
            return body;
        }
        int end = Character.isHighSurrogate(body.charAt(BODY_LIMIT_CHARS - 1)) ? BODY_LIMIT_CHARS - 1 : BODY_LIMIT_CHARS;
        return Redactor.redact(body.substring(0, end)) + "\n[kept the first " + end + " of " + body.length()
                + " characters]";
    }
}
