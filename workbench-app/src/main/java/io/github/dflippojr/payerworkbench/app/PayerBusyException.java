package io.github.dflippojr.payerworkbench.app;

/**
 * Another run held the synthetic payer for longer than {@code workbench.request-timeout}, so this one was
 * refused rather than left waiting. Runs against one synthetic payer take turns because its faults are shared.
 */
final class PayerBusyException extends RuntimeException {

    PayerBusyException(String payerId) {
        super("another run against " + payerId + " is in progress; try again when it finishes");
    }
}
