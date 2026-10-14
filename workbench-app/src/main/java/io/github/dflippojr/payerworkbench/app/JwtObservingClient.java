package io.github.dflippojr.payerworkbench.app;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Flow;
import java.util.function.Consumer;

/**
 * Observes only the non-secret claims of the JWT the SDK actually sends.
 * The SDK listener masks Authorization and drops token request bodies, so this
 * transport decorator reads the claims before delegation; it never retains the token.
 * A token request's {@code client_assertion} and a {@code Bearer} header go to separate
 * callbacks: once a SMART token endpoint issues a JWT access token, the Bearer header
 * on the hook call is that access token, not the client's own assertion.
 * Request construction, authentication, sending and retries belong to the SDK.
 */
final class JwtObservingClient extends ForwardingHttpClient {
    private final Consumer<String> assertion;
    private final Consumer<String> bearer;

    JwtObservingClient(HttpClient delegate, Consumer<String> assertion, Consumer<String> bearer) {
        super(delegate);
        this.assertion = assertion;
        this.bearer = bearer;
    }

    @Override
    protected HttpRequest prepare(HttpRequest request) {
        if (request.headers().firstValue("Content-Type").orElse("").startsWith("application/x-www-form-urlencoded")) {
            request.bodyPublisher().ifPresent(publisher -> publisher.subscribe(new AssertionObserver(assertion)));
        }
        request.headers().firstValue("Authorization").filter(v -> v.startsWith("Bearer "))
                .ifPresent(v -> bearer.accept(v.substring(7)));
        return request;
    }

    /** SDK string publishers complete synchronously; only decoded claims leave the callback. */
    private static final class AssertionObserver implements Flow.Subscriber<ByteBuffer> {
        private final ByteArrayOutputStream body = new ByteArrayOutputStream();
        private final Consumer<String> observe;
        AssertionObserver(Consumer<String> observe) { this.observe = observe; }
        @Override public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
        @Override public void onNext(ByteBuffer chunk) {
            byte[] bytes = new byte[chunk.remaining()];
            chunk.get(bytes);
            body.writeBytes(bytes);
        }
        @Override public void onError(Throwable error) { body.reset(); }
        @Override public void onComplete() {
            for (String part : body.toString(StandardCharsets.UTF_8).split("&")) {
                if (part.startsWith("client_assertion=")) {
                    observe.accept(URLDecoder.decode(part.substring("client_assertion=".length()), StandardCharsets.UTF_8));
                }
            }
            body.reset();
        }
    }

}
