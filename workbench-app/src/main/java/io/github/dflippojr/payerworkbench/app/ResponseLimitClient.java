package io.github.dflippojr.payerworkbench.app;

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
 */
final class ResponseLimitClient extends ForwardingHttpClient {
    private final long limit;

    ResponseLimitClient(HttpClient delegate, long limit) {
        super(delegate);
        if (limit <= 0) {
            throw new IllegalArgumentException("workbench.max-response-bytes must be positive");
        }
        this.limit = limit;
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
        return info -> new LimitedSubscriber<>(handler.apply(info), limit, info);
    }

    /**
     * Passes bytes to the caller's subscriber until the limit. The batch that crosses it is cut at
     * the limit, the upstream subscription is cancelled and the caller's subscriber completes, so
     * its body is the first {@code limit} bytes; {@link #getBody()} then fails with that body.
     */
    private static final class LimitedSubscriber<T> implements HttpResponse.BodySubscriber<T> {
        private final HttpResponse.BodySubscriber<T> delegate;
        private final long limit;
        private final HttpResponse.ResponseInfo info;
        private Flow.Subscription subscription;
        private long received;
        private boolean done;
        /** Bytes received when the limit was crossed, or -1 while under it. */
        private volatile long cutAt = -1;

        LimitedSubscriber(HttpResponse.BodySubscriber<T> delegate, long limit, HttpResponse.ResponseInfo info) {
            this.delegate = delegate;
            this.limit = limit;
            this.info = info;
        }

        @Override
        public CompletionStage<T> getBody() {
            return delegate.getBody().thenCompose(body -> {
                long cut = cutAt;
                return cut < 0 ? CompletableFuture.completedFuture(body)
                        : CompletableFuture.failedFuture(new ResponseTooLargeException(limit, cut, info.statusCode(),
                                info.headers(), body instanceof String s ? s : null));
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
