package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/**
 * Stops reading any response body at {@code limit} bytes ({@code workbench.max-response-bytes}),
 * so a payer that sends a huge discovery or hook body cannot fill the heap. The call then fails
 * with a {@link ResponseTooLargeException} that carries the status, headers and the body up to
 * the limit; nothing past the limit is buffered.
 *
 * <p>Bytes alone do not bound what parsing a body builds: 4 MiB of {@code {}} is 1.4 million objects.
 * So a text body that arrived in full is also counted, as a stream of JSON tokens, and one holding
 * more than {@code maxJsonValues} values ({@code workbench.max-response-json-values}) fails the same
 * way before the SDK parses it.
 */
final class ResponseLimitClient extends ForwardingHttpClient {
    private static final JsonFactory JSON = new JsonFactory();

    private final long limit;
    private final int maxJsonValues;

    ResponseLimitClient(HttpClient delegate, long limit) {
        this(delegate, limit, WorkbenchProperties.DEFAULT_MAX_RESPONSE_JSON_VALUES);
    }

    ResponseLimitClient(HttpClient delegate, long limit, int maxJsonValues) {
        super(delegate);
        if (limit <= 0) {
            throw new IllegalArgumentException("workbench.max-response-bytes must be positive");
        }
        if (maxJsonValues <= 0) {
            throw new IllegalArgumentException("workbench.max-response-json-values must be positive");
        }
        this.limit = limit;
        this.maxJsonValues = maxJsonValues;
    }

    /**
     * Whether {@code body} holds more than {@code max} JSON values. Counting stops at the first value
     * past {@code max}, or where the text stops being JSON: the SDK rejects such a body anyway.
     */
    static boolean holdsMoreJsonValuesThan(String body, int max) {
        int values = 0;
        try (JsonParser parser = JSON.createParser(body)) {
            for (JsonToken token = parser.nextToken(); token != null; token = parser.nextToken()) {
                if (token.isScalarValue() || token.isStructStart()) {
                    if (++values > max) {
                        return true;
                    }
                }
            }
        } catch (IOException e) {
            // Not JSON past this point; what was counted stands.
        }
        return false;
    }

    @Override
    protected HttpRequest prepare(HttpRequest request) {
        return request;
    }

    /** Fails with the {@link ResponseTooLargeException} itself rather than the client's wrapper around it. */
    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        try {
            return super.send(request, limited(handler));
        } catch (IOException e) {
            ResponseTooLargeException tooLarge = ResponseTooLargeException.in(e);
            throw tooLarge == null ? e : tooLarge;
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        return super.sendAsync(request, limited(handler));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler,
                                                           HttpResponse.PushPromiseHandler<T> pushHandler) {
        return super.sendAsync(request, limited(handler), pushHandler);
    }

    private <T> HttpResponse.BodyHandler<T> limited(HttpResponse.BodyHandler<T> handler) {
        return info -> new LimitedSubscriber<>(handler.apply(info), limit, maxJsonValues, info);
    }

    /**
     * Passes bytes to the caller's subscriber until the limit. The batch that crosses it is cut at
     * the limit, the upstream subscription is cancelled and the caller's subscriber completes, so
     * its body is the first {@code limit} bytes; {@link #getBody()} then fails with that body. A
     * text body that arrived in full fails there too when it holds more than {@code maxJsonValues}.
     */
    private static final class LimitedSubscriber<T> implements HttpResponse.BodySubscriber<T> {
        private final HttpResponse.BodySubscriber<T> delegate;
        private final long limit;
        private final int maxJsonValues;
        private final HttpResponse.ResponseInfo info;
        private Flow.Subscription subscription;
        private long received;
        private boolean done;
        /** Bytes received when the limit was crossed, or -1 while under it. */
        private volatile long cutAt = -1;

        LimitedSubscriber(HttpResponse.BodySubscriber<T> delegate, long limit, int maxJsonValues,
                          HttpResponse.ResponseInfo info) {
            this.delegate = delegate;
            this.limit = limit;
            this.maxJsonValues = maxJsonValues;
            this.info = info;
        }

        @Override
        public CompletionStage<T> getBody() {
            return delegate.getBody().thenCompose(body -> {
                long cut = cutAt;
                if (cut >= 0) {
                    return CompletableFuture.failedFuture(new ResponseTooLargeException(limit, cut, info.statusCode(),
                            info.headers(), body instanceof String s ? s : null));
                }
                if (body instanceof String s && holdsMoreJsonValuesThan(s, maxJsonValues)) {
                    return CompletableFuture.failedFuture(ResponseTooLargeException.jsonValues(maxJsonValues, received,
                            info.statusCode(), info.headers(), s));
                }
                return CompletableFuture.completedFuture(body);
            });
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            delegate.onSubscribe(subscription);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (done) {
                return;
            }
            long size = 0;
            for (ByteBuffer item : items) {
                size += item.remaining();
            }
            if (received + size <= limit) {
                received += size;
                delegate.onNext(items);
                return;
            }
            long allowance = limit - received;
            List<ByteBuffer> kept = new ArrayList<>();
            for (ByteBuffer item : items) {
                if (allowance <= 0) {
                    break;
                }
                int take = (int) Math.min(item.remaining(), allowance);
                kept.add(item.slice(item.position(), take));
                allowance -= take;
            }
            received += size;
            done = true;
            cutAt = received;
            subscription.cancel();
            if (!kept.isEmpty()) {
                delegate.onNext(kept);
            }
            delegate.onComplete();
        }

        @Override
        public void onError(Throwable throwable) {
            if (!done) {
                done = true;
                delegate.onError(throwable);
            }
        }

        @Override
        public void onComplete() {
            if (!done) {
                done = true;
                delegate.onComplete();
            }
        }
    }
}
