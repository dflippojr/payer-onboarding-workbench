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
        if (request.headers().firstValue("Content-Type").orElse("").startsWith("application/x-www-form-urlencoded")) {
            request.bodyPublisher().ifPresent(publisher -> publisher.subscribe(new AssertionObserver(observe)));
        }
        request.headers().firstValue("Authorization").filter(v -> v.startsWith("Bearer "))
                .ifPresent(v -> observe.accept(v.substring(7)));
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
