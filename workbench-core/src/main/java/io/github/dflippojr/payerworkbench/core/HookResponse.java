package io.github.dflippojr.payerworkbench.core;

import java.util.Objects;

/**
 * A call to one CDS Hooks service and what came back.
 *
 * @param serviceId the service {@code id} from the discovery response
 * @param hook the hook name, e.g. {@code order-sign}
 * @param sampleId identifier of the synthetic request payload sent; may be {@code null}
 * @param exchange the HTTP exchange, redacted
 */
public record HookResponse(
        String serviceId,
        String hook,
        String sampleId,
        HttpExchange exchange
) {
    public HookResponse {
        Objects.requireNonNull(serviceId, "serviceId");
        Objects.requireNonNull(exchange, "exchange");
    }
}
