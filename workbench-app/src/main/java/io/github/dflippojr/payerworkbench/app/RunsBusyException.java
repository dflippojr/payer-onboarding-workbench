package io.github.dflippojr.payerworkbench.app;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

/**
 * {@code workbench.max-concurrent-runs} custom-endpoint runs are already in flight, so this one was
 * refused rather than queued. Each run may hold a few payer bodies of up to
 * {@code workbench.max-response-bytes} while it parses them; this bounds how many the heap holds at once.
 * Answered with 503 and a hint to retry, and audited {@code runs_busy}.
 */
final class RunsBusyException extends RunRejection {

    RunsBusyException(int maxConcurrentRuns) {
        super("runs_busy", HttpStatus.SERVICE_UNAVAILABLE,
                maxConcurrentRuns + " custom-endpoint runs are already in progress (workbench.max-concurrent-runs); "
                        + "try again when one finishes");
    }

    @Override
    HttpHeaders headers() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, "5");
        return headers;
    }
}
