package io.github.dflippojr.payerworkbench.app;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;

/**
 * Sends the run's correlation id as {@value #HEADER} on every request the SDK
 * makes through it (discovery, token and hook calls), replacing any value
 * already set, so a payer can find the call in its own logs.
 */
final class RequestIdClient extends ForwardingHttpClient {
    static final String HEADER = "X-Request-Id";

    private final String requestId;

    RequestIdClient(HttpClient delegate, String requestId) {
        super(delegate);
        this.requestId = requestId;
    }

    @Override
    protected HttpRequest prepare(HttpRequest request) {
        return HttpRequest.newBuilder(request, (name, value) -> !name.equalsIgnoreCase(HEADER))
                .header(HEADER, requestId)
                .build();
    }
}
