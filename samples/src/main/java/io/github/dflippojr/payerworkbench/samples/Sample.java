package io.github.dflippojr.payerworkbench.samples;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import java.util.Objects;
import java.util.UUID;

/**
 * A loaded sample: its metadata and the request, as a {@code client-sdk}
 * {@link CdsHookRequest} ready to send.
 *
 * <p>The request carries the sample's fixed {@code hookInstance}. CDS Hooks
 * expects a new one per invocation, so call {@link #withNewHookInstance()}
 * before sending a sample more than once.
 */
public record Sample(SampleMetadata metadata, PrefetchVariant variant, CdsHookRequest request) {
    public Sample {
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(variant, "variant");
        Objects.requireNonNull(request, "request");
    }

    public String id() {
        return metadata.id();
    }

    /** A copy with a random {@code hookInstance}. */
    public Sample withNewHookInstance() {
        var fresh = new CdsHookRequest(request.hook(), UUID.randomUUID().toString(), request.fhirServer(),
                request.fhirAuthorization(), request.context(), request.prefetch());
        return new Sample(metadata, variant, fresh);
    }

    /** The request as a JSON tree. */
    public JsonNode toJson() {
        return FhirResources.MAPPER.valueToTree(request);
    }

    /** The request as pretty-printed JSON, with prefetch keys in a stable order. */
    public String toJsonString() {
        return FhirResources.pretty(request);
    }
}
