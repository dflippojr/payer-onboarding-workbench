package io.github.dflippojr.payerworkbench.mock;

import java.util.Optional;

/**
 * A deliberate misbehavior a {@link MockPayer} can be switched into, so the
 * workbench has known failures to diagnose. Every fault is off by default and
 * deterministic: while it is on, every affected request fails the same way.
 */
public enum Fault {

    /**
     * Hook calls ({@code POST /cds-services/{id}}) wait {@link FaultSettings#slowResponseDelay()}
     * before they are handled. Discovery, the token endpoint and admin stay fast.
     */
    SLOW_RESPONSE("slow-response"),

    /** Hook calls are rejected with 401 because the credential is treated as expired. */
    EXPIRED_TOKEN_401("expired-token-401"),

    /** Hook calls are rejected with 401 because the payer expects a different audience. */
    WRONG_AUDIENCE_REJECT("wrong-audience-reject"),

    /** Hook responses contain cards with no {@code summary} and no {@code indicator}. */
    MALFORMED_CARD("malformed-card"),

    /** order-sign determinations omit the assertion id and use an invalid covered code. */
    COVERAGE_INFO_INCOMPLETE("coverage-info-incomplete"),

    /** {@code GET /cds-services} returns 500. */
    DISCOVERY_500("discovery-500"),

    /**
     * Hook calls return 400 when a prefetch key the service declared is absent
     * (and its template could have been resolved from the context). With the
     * fault off, missing prefetch is tolerated.
     */
    PREFETCH_MISSING_400("prefetch-missing-400"),

    /** The TLS server presents a certificate from a second, untrusted test CA. */
    UNTRUSTED_CERTIFICATE("untrusted-certificate"),

    /** The TLS server presents a trusted certificate that expired yesterday. */
    EXPIRED_CERTIFICATE("expired-certificate"),

    /** The TLS server presents a trusted certificate for another hostname only. */
    HOSTNAME_MISMATCH("hostname-mismatch");

    private final String id;

    Fault(String id) {
        this.id = id;
    }

    /** The kebab-case name used by the admin endpoint, e.g. {@code slow-response}. */
    public String id() {
        return id;
    }

    /** Looks a fault up by {@link #id()}. */
    public static Optional<Fault> fromId(String id) {
        for (Fault fault : values()) {
            if (fault.id.equals(id)) {
                return Optional.of(fault);
            }
        }
        return Optional.empty();
    }
}
