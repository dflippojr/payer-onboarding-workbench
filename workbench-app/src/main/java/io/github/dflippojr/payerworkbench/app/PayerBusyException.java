package io.github.dflippojr.payerworkbench.app;

import org.springframework.http.HttpStatus;

/**
 * Another run held the synthetic payer for longer than {@code workbench.request-timeout}, so this one was
 * refused rather than left waiting. Runs against one synthetic payer take turns because its faults are shared.
 * Answered with 409 and audited {@code payer_busy}.
 */
final class PayerBusyException extends RunRejection {

    PayerBusyException(String payerId) {
        super("payer_busy", HttpStatus.CONFLICT,
                "another run against " + payerId + " is in progress; try again when it finishes");
    }
}
