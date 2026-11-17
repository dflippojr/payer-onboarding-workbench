package io.github.dflippojr.payerworkbench.app;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

/**
 * A run or report request the workbench refused before any run started. It carries the audit reason code, the HTTP
 * status and a message that is safe to show the caller, so {@link WorkbenchApiController}'s one handler answers with
 * the problem detail and writes the reason into the audit trail, and no reason travels on its own.
 *
 * <p>It is an {@link IllegalArgumentException} so a programmatic caller of {@link OnboardingRunner#run} keeps catching
 * a refused request as before.
 */
class RunRejection extends IllegalArgumentException {

    private final String reasonCode;
    private final HttpStatus status;

    /** A 400: the request itself is not acceptable. */
    RunRejection(String reasonCode, String message) {
        this(reasonCode, HttpStatus.BAD_REQUEST, message);
    }

    RunRejection(String reasonCode, HttpStatus status, String message) {
        super(message);
        this.reasonCode = reasonCode;
        this.status = status;
    }

    /** The fixed audit reason code, one of the codes the README's audit section lists. */
    String reasonCode() {
        return reasonCode;
    }

    HttpStatus status() {
        return status;
    }

    /** Headers the refusal adds to the response; none unless a subclass says otherwise. */
    HttpHeaders headers() {
        return HttpHeaders.EMPTY;
    }
}
