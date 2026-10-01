package io.github.dflippojr.payerworkbench.core;

import java.util.Objects;

/**
 * A call to one CDS Hooks service and what came back.
 *
 * @param serviceId the service {@code id} from the discovery response
 * @param hook the hook name, e.g. {@code order-sign}
 * @param sampleId identifier of the synthetic request payload sent; may be {@code null}
 * @param exchange the HTTP exchange, redacted
 * @param clientJwt non-secret claims of the CDS Hooks client JWT sent as the bearer
 *     token; {@code null} if the call carried no such JWT
 */
public record HookResponse(
        String serviceId,
        String hook,
        String sampleId,
        HttpExchange exchange,
        JwtClaims clientJwt
) {
    public HookResponse {
        Objects.requireNonNull(serviceId, "serviceId");
        Objects.requireNonNull(exchange, "exchange");
    }

    /** A hook call that carried no CDS Hooks client JWT. */
    public HookResponse(String serviceId, String hook, String sampleId, HttpExchange exchange) {
        this(serviceId, hook, sampleId, exchange, null);
    }
}
