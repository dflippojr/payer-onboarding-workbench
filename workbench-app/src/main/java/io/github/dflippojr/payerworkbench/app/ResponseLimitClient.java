package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

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
 *
 * <p>The JDK's request timeout stops at the response headers, so a payer that sends headers and then
 * stalls would hold the run, its thread and the partial body for good. {@link #send} therefore gives
 * the whole call, body included, a deadline: the request's own timeout, or {@code timeout} when it has
 * none. Past it the call is cancelled, the partial body is dropped and the call fails with an
 * {@link HttpTimeoutException}.
 */
final class ResponseLimitClient extends ForwardingHttpClient {
    private static final JsonFactory JSON = new JsonFactory();

    private final long limit;
    private final int maxJsonValues;
    private final Duration timeout;

    ResponseLimitClient(HttpClient delegate, long limit) {
        this(delegate, limit, WorkbenchProperties.DEFAULT_MAX_RESPONSE_JSON_VALUES);
    }

    ResponseLimitClient(HttpClient delegate, long limit, int maxJsonValues) {
        this(delegate, limit, maxJsonValues, WorkbenchProperties.DEFAULT_REQUEST_TIMEOUT);
    }

    ResponseLimitClient(HttpClient delegate, long limit, int maxJsonValues, Duration timeout) {
        super(delegate);
        if (limit <= 0) {
            throw new IllegalArgumentException("workbench.max-response-bytes must be positive");
        }
        if (maxJsonValues <= 0) {
            throw new IllegalArgumentException("workbench.max-response-json-values must be positive");
        }
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("workbench.request-timeout must be positive");
        }
        this.limit = limit;
        this.maxJsonValues = maxJsonValues;
        this.timeout = timeout;
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

    /**
     * Sends {@code request} and waits for the whole response, body included, until the request's timeout
     * (or {@code timeout}). Fails with the {@link ResponseTooLargeException} itself rather than the client's
     * wrapper around it.
     */
    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        Duration deadline = request.timeout().orElse(timeout);
        List<LimitedSubscriber<T>> reading = new CopyOnWriteArrayList<>();
        CompletableFuture<HttpResponse<T>> call = super.sendAsync(request, limited(handler, reading::add));
        try {
            return call.get(deadline.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            HttpTimeoutException timedOut = new HttpTimeoutException("request timed out: the response did not arrive "
                    + "in full within " + deadline.toMillis() + " ms");
            call.cancel(true);
            reading.forEach(subscriber -> subscriber.abort(timedOut));
            throw timedOut;
        } catch (InterruptedException e) {
            call.cancel(true);
            reading.forEach(subscriber -> subscriber.abort(e));
            throw e;
        } catch (ExecutionException e) {
            throw failure(e.getCause());
        }
    }

    /** What {@link #send} throws for a call that failed with {@code cause}. */
    private static IOException failure(Throwable cause) {
        ResponseTooLargeException tooLarge = ResponseTooLargeException.in(cause);
        if (tooLarge != null) {
            return tooLarge;
        }
        if (cause instanceof IOException io) {
            return io;
        }
        if (cause instanceof RuntimeException runtime) {
            throw runtime;
        }
        if (cause instanceof Error error) {
            throw error;
        }
        return new IOException(cause.getMessage(), cause);
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
        return limited(handler, subscriber -> { });
    }

    private <T> HttpResponse.BodyHandler<T> limited(HttpResponse.BodyHandler<T> handler,
                                                    Consumer<LimitedSubscriber<T>> started) {
        return info -> {
            LimitedSubscriber<T> subscriber = new LimitedSubscriber<>(handler.apply(info), limit, maxJsonValues, info);
            started.accept(subscriber);
            return subscriber;
        };
    }

    /**
     * Passes bytes to the caller's subscriber until the limit. The batch that crosses it is cut at
     * the limit, the upstream subscription is cancelled and the caller's subscriber completes, so
     * its body is the first {@code limit} bytes; {@link #getBody()} then fails with that body. A
     * text body that arrived in full fails there too when it holds more than {@code maxJsonValues}.
     * {@link #abort} drops a body that is still arriving; the callbacks are synchronized because it
     * comes from the caller's thread rather than the client's.
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
        public synchronized void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            delegate.onSubscribe(subscription);
        }

        /** Stops reading and fails the body with {@code failure}, unless it already ended. */
        synchronized void abort(Throwable failure) {
            if (done) {
                return;
            }
            done = true;
            if (subscription != null) {
                subscription.cancel();
            }
            delegate.onError(failure);
        }

        @Override
        public synchronized void onNext(List<ByteBuffer> items) {
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
        public synchronized void onError(Throwable throwable) {
            if (!done) {
                done = true;
                delegate.onError(throwable);
            }
        }

        @Override
        public synchronized void onComplete() {
            if (!done) {
                done = true;
                delegate.onComplete();
            }
        }
    }
}
