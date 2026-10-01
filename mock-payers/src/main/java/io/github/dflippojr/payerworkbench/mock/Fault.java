package io.github.dflippojr.payerworkbench.mock;

import java.util.Optional;

/**
 * A deliberate misbehavior a {@link MockPayer} can be switched into, so the
 * workbench has known failures to diagnose. Every fault is off by default and
 * deterministic: while it is on, every affected request fails the same way.
 */
public enum Fault {

    /** Every non-admin request waits {@link FaultSettings#slowResponseDelay()} before it is handled. */
    SLOW_RESPONSE("slow-response"),

    /** Hook calls are rejected with 401 because the credential is treated as expired. */
    EXPIRED_TOKEN_401("expired-token-401"),

    /** Hook calls are rejected with 401 because the payer expects a different audience. */
    WRONG_AUDIENCE_REJECT("wrong-audience-reject"),

    /** Hook responses contain cards with no {@code summary} and no {@code indicator}. */
    MALFORMED_CARD("malformed-card"),

    /** {@code GET /cds-services} returns 500. */
    DISCOVERY_500("discovery-500"),

    /**
     * Hook calls return 400 when a prefetch key the service declared is absent
     * (and its template could have been resolved from the context). With the
     * fault off, missing prefetch is tolerated.
     */
    PREFETCH_MISSING_400("prefetch-missing-400"),

    /**
     * Every non-admin request returns 426 Upgrade Required, as a plain-HTTP
     * endpoint does when it only accepts TLS. Simulated: the mock never serves TLS.
     */
    TLS_REQUIRED("tls-required");

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
