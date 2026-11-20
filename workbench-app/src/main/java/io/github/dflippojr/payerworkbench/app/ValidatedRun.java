package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.samples.SampleMetadata;

import java.time.Duration;
import java.util.List;

/**
 * A run request that passed every check, with what it names looked up: the synthetic payer, its faults and the
 * {@code slow-response} delay, or the custom endpoint's setup. The connection edits stay on the request.
 * {@link RunRequestValidator} builds it.
 *
 * @param payer             the synthetic payer, or null for a custom-endpoint run
 * @param slowResponseDelay the delay a {@code slow-response} fault uses; null for a custom-endpoint run
 * @param custom            the custom endpoint's guard, credential store and record, or null for a synthetic run
 */
record ValidatedRun(RunRequest request, SampleMetadata sample, MockPayer payer, List<Fault> faults,
                    Duration slowResponseDelay, CustomEndpointSetup custom) {
}
