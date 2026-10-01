package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.HttpExchange;

import java.util.List;
import java.util.Map;

/**
 * An {@link HttpExchange} as the UI shows it, with latency in milliseconds. The
 * headers and bodies are the exchange's, which were redacted when it was built.
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
    static ExchangeView of(HttpExchange e) {
        return new ExchangeView(e.method(), e.url(), e.status(), e.latency().toMillis(), e.requestHeaders(),
                e.requestBody(), e.responseHeaders(), e.responseBody(), e.transportError());
    }
}
