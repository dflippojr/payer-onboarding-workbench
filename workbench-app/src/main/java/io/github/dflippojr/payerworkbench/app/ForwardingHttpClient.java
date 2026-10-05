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
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * A transport decorator for the SDK's {@link HttpClient}: every request passes
 * through {@link #prepare} on its way to the delegate, and the transport
 * configuration is the delegate's.
 */
abstract class ForwardingHttpClient extends HttpClient {
    private final HttpClient delegate;

    ForwardingHttpClient(HttpClient delegate) {
        this.delegate = delegate;
    }

    /** The request to send in place of {@code request}. */
    protected abstract HttpRequest prepare(HttpRequest request);

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        return delegate.send(prepare(request), handler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        return delegate.sendAsync(prepare(request), handler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler,
                                                           HttpResponse.PushPromiseHandler<T> pushHandler) {
        return delegate.sendAsync(prepare(request), handler, pushHandler);
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
