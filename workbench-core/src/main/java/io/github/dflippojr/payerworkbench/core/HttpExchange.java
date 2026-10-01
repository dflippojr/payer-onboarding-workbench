package io.github.dflippojr.payerworkbench.core;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * One HTTP request/response pair observed during a run. The constructor redacts
 * credential headers (see {@link Redactor#redactHeaders(Map)}) and passes both
 * bodies through {@link Redactor#redact(String)}, so an instance never holds a
 * token, client secret or private key.
 *
 * @param method HTTP method, e.g. {@code GET}
 * @param url the full request URL
 * @param status HTTP status code, or {@link #NO_RESPONSE} if no response arrived
 * @param latency time from sending the request to receiving the full response (or failing)
 * @param requestHeaders request headers, redacted
 * @param requestBody request body, redacted; may be {@code null}
 * @param responseHeaders response headers, redacted
 * @param responseBody response body, redacted; may be {@code null}
 * @param transportError why no response arrived (connection refused, TLS failure,
 *     timeout); {@code null} when a response was received
 */
public record HttpExchange(
        String method,
        String url,
        int status,
        Duration latency,
        Map<String, List<String>> requestHeaders,
        String requestBody,
        Map<String, List<String>> responseHeaders,
        String responseBody,
        String transportError
) {
    /** {@link #status()} value when no HTTP response was received. */
    public static final int NO_RESPONSE = 0;

    public HttpExchange {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(url, "url");
        latency = latency == null ? Duration.ZERO : latency;
        requestHeaders = Redactor.redactHeaders(requestHeaders);
        requestBody = Redactor.redact(requestBody);
        responseHeaders = Redactor.redactHeaders(responseHeaders);
        responseBody = Redactor.redact(responseBody);
        transportError = Redactor.redact(transportError);
    }

    /** Whether an HTTP response (of any status) was received. */
    public boolean responded() {
        return status != NO_RESPONSE;
    }
}
