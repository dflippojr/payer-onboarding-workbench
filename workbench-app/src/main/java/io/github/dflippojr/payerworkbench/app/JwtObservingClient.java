package io.github.dflippojr.payerworkbench.app;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.function.Consumer;

/**
 * Observes only the non-secret claims of the JWT the SDK actually sends.
 * The SDK listener masks Authorization before reporting it, so this transport
 * decorator reads the claims before delegation; it never retains the token.
 * Request construction, authentication, sending and retries belong to the SDK.
 */
final class JwtObservingClient extends ForwardingHttpClient {
    private final Consumer<String> observe;

    JwtObservingClient(HttpClient delegate, Consumer<String> observe) {
        super(delegate);
        this.observe = observe;
    }

    @Override
    protected HttpRequest prepare(HttpRequest request) {
        request.headers().firstValue("Authorization").filter(v -> v.startsWith("Bearer "))
                .ifPresent(v -> observe.accept(v.substring(7)));
        return request;
    }
}
