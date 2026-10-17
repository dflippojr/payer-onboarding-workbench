package io.github.dflippojr.payerworkbench.app;

/**
 * {@code workbench.max-concurrent-runs} custom-endpoint runs are already in flight, so this one was
 * refused rather than queued. Each run may hold a few payer bodies of up to
 * {@code workbench.max-response-bytes} while it parses them; this bounds how many the heap holds at once.
 */
final class RunsBusyException extends RuntimeException {

    RunsBusyException(int maxConcurrentRuns) {
        super(maxConcurrentRuns + " custom-endpoint runs are already in progress (workbench.max-concurrent-runs); "
                + "try again when one finishes");
    }
}
