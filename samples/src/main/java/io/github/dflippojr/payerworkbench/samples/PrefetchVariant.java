package io.github.dflippojr.payerworkbench.samples;

/**
 * Which prefetch keys a sample request carries.
 */
public enum PrefetchVariant {
    /** The CRD keys a spec-conformant payer (mock payer A) advertises: {@code patient}, {@code encounter}, {@code coverage}. */
    STANDARD,

    /**
     * The non-standard keys mock payer B uses, in the style of the HL7 CRD
     * reference implementation: {@code coverage} becomes {@code coverageBundle},
     * and the DeviceRequests in {@code draftOrders} are also sent as
     * {@code deviceRequestBundle}, a searchset with the patient, requester and
     * coverage they reference included. {@code patient} and {@code encounter}
     * are unchanged. A sample sent without prefetch stays without prefetch.
     */
    PAYER_B
}
