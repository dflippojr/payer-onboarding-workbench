package io.github.dflippojr.payerworkbench.app;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * Observes only the non-secret claims of the JWT the SDK actually sends.
 * The SDK listener masks Authorization before reporting it, so this transport
 * decorator reads the claims before delegation; it never retains the token.
 * Request construction, authentication, sending and retries belong to the SDK.
 */
final class JwtObservingClient extends HttpClient {
    private final HttpClient delegate;
    private final Consumer<String> observe;

    JwtObservingClient(HttpClient delegate, Consumer<String> observe) {
        this.delegate = delegate;
        this.observe = observe;
    }

    private void observe(HttpRequest request) {
        request.headers().firstValue("Authorization").filter(v -> v.startsWith("Bearer "))
                .ifPresent(v -> observe.accept(v.substring(7)));
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        observe(request);
        return delegate.send(request, handler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        observe(request);
        return delegate.sendAsync(request, handler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler,
                                                           HttpResponse.PushPromiseHandler<T> pushHandler) {
        observe(request);
        return delegate.sendAsync(request, handler, pushHandler);
    }

    @Override public Optional<CookieHandler> cookieHandler() { return delegate.cookieHandler(); }
    @Override public Optional<Duration> connectTimeout() { return delegate.connectTimeout(); }
    @Override public Redirect followRedirects() { return delegate.followRedirects(); }
    @Override public Optional<ProxySelector> proxy() { return delegate.proxy(); }
    @Override public SSLContext sslContext() { return delegate.sslContext(); }
    @Override public SSLParameters sslParameters() { return delegate.sslParameters(); }
    @Override public Optional<Authenticator> authenticator() { return delegate.authenticator(); }
    @Override public Version version() { return delegate.version(); }
    @Override public Optional<Executor> executor() { return delegate.executor(); }
}
