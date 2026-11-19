package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import io.github.dflippojr.payerworkbench.samples.SampleMetadata;

import java.time.Duration;
import java.util.List;

/**
 * The one home of run validation: turns a {@link RunRequest} into a {@link ValidatedRun}, or refuses it with a
 * {@link RunRejection} that carries the audit reason code, checking in the order the workbench always has.
 */
final class RunRequestValidator {

    private final SyntheticPayers payers;
    private final SampleCatalog samples;
    private final WorkbenchProperties properties;

    RunRequestValidator(SyntheticPayers payers, SampleCatalog samples, WorkbenchProperties properties) {
        this.payers = payers;
        this.samples = samples;
        this.properties = properties;
    }

    static final String CUSTOM_DISABLED = "Custom endpoints are disabled. Set "
            + "workbench.custom-endpoints.enabled=true to run against your own payer endpoint.";

    /**
     * Checks {@code request} in the order the workbench always has, and refuses it with the first rule it breaks.
     * Each refusal carries its audit reason code, which {@link WorkbenchApiController} writes in one place.
     *
     * @throws RunRejection if the request breaks a rule
     */
    ValidatedRun validate(RunRequest request) {
        if (request.payerId() == null || request.sampleId() == null) {
            throw new RunRejection("missing_input", "payerId and sampleId are required");
        }
        SampleMetadata sample = samples.list().stream()
                .filter(s -> s.id().equals(request.sampleId()))
                .findFirst()
                .orElse(null);
        return request.customEndpoint() != null ? validateCustom(request, sample) : validateSynthetic(request, sample);
    }

    private ValidatedRun validateSynthetic(RunRequest request, SampleMetadata sample) {
        MockPayer payer = payers.payer(request.payerId()).orElse(null);
        if (payer == null) {
            // The detail names the payer, but an unknown sample has always been the audited reason (RunRejectionPinTest).
            throw new RunRejection(sample == null ? "unknown_sample" : "unknown_payer",
                    "Unknown payerId: " + request.payerId());
        }
        if (sample == null) {
            throw new RunRejection("unknown_sample", "Unknown sampleId: " + request.sampleId());
        }
        List<Fault> faults = request.faults().stream()
                .map(id -> Fault.fromId(id).orElseThrow(() -> new RunRejection("unknown_fault", "Unknown fault: " + id)))
                .toList();
        checkSlowResponseDelay(request);
        checkSuffix(request, payers.store().findByPayerIdAndEnvironment(request.payerId(), request.environment())
                .map(ConnectionRecord::baseUrl).orElse(null));
        Duration delay = request.slowResponseDelayMs() == null
                ? properties.slowResponseDelay()
                : Duration.ofMillis(request.slowResponseDelayMs());
        return new ValidatedRun(request, sample, payer, faults, delay, null);
    }

    private ValidatedRun validateCustom(RunRequest request, SampleMetadata sample) {
        if (!properties.customEndpoints().enabled()) {
            // The detail says custom endpoints are off, but an unknown sample has always been the audited reason.
            throw new RunRejection(sample == null ? "unknown_sample" : "custom_disabled", CUSTOM_DISABLED);
        }
        if (sample == null) {
            throw new RunRejection("unknown_sample", "Unknown sampleId: " + request.sampleId());
        }
        if (!request.faults().isEmpty()) {
            throw CustomEndpointSetup.refuse("Faults only apply to the synthetic payers");
        }
        CustomEndpointSetup custom = new CustomEndpointSetup(request);
        checkSuffix(request, custom.record().baseUrl());
        return new ValidatedRun(request, sample, null, List.of(), null, custom);
    }

    /**
     * Refuses a {@code slowResponseDelayMs} outside 0 to {@link WorkbenchProperties#maxSlowResponseDelay()}. Above the
     * maximum, the workbench gives up on the hook call at {@code workbench.request-timeout} but the mock payer would
     * keep sleeping for the whole delay. A negative delay reaches the mock payer's fault setup, which refuses it only
     * after the payer lock and once a run id exists (#210), so both bounds are checked here, before any run starts.
     */
    private void checkSlowResponseDelay(RunRequest request) {
        Long delay = request.slowResponseDelayMs();
        long max = properties.maxSlowResponseDelay().toMillis();
        if (delay == null || (delay >= 0 && delay <= max)) { return; }
        throw new RunRejection("invalid_slow_response_delay", delay < 0
                ? "slowResponseDelayMs must be between 0 and " + max + " (workbench.request-timeout plus 1 s)"
                : "slowResponseDelayMs must be at most " + max + " (workbench.request-timeout plus 1 s)");
    }

    private static final String SUFFIX_RULE = "baseUrlSuffix may only add path segments to the base URL: "
            + "it must start with / and can't contain . or .. segments (raw or as %2e), "
            + "@, ?, #, \\, whitespace or control characters";

    /**
     * Refuses a {@code baseUrlSuffix} that would send the run anywhere but a path under the base URL,
     * before anything is sent or recorded. With no stored base URL only the suffix itself is checked;
     * the run then fails at resolve as before.
     */
    private static void checkSuffix(RunRequest request, String baseUrl) {
        String suffix = request.connection().baseUrlSuffix();
        if (!isSet(suffix)) { return; }
        try { withSuffix(baseUrl == null ? "https://localhost" : baseUrl, suffix); }
        catch (IllegalArgumentException e) {
            throw new RunRejection("invalid_connection_edit", e.getMessage());
        }
    }

    /**
     * {@code baseUrl} with {@code suffix} appended, as long as the result keeps the base URL's scheme,
     * host and port and gains no user info, query or fragment, and the suffix has no {@code .} or
     * {@code ..} segment, which the payer's server would resolve to a path outside the base URL's.
     *
     * @throws IllegalArgumentException otherwise
     */
    static String withSuffix(String baseUrl, String suffix) {
        String trimmed = suffix.trim();
        if (!trimmed.startsWith("/") || trimmed.chars().anyMatch(c -> c == '@' || c == '?' || c == '#' || c == '\\'
                || Character.isWhitespace(c) || Character.isISOControl(c))) {
            throw new IllegalArgumentException(SUFFIX_RULE);
        }
        for (String segment : trimmed.split("/", -1)) {
            String decoded = segment.replaceAll("(?i)%2e", ".");
            if (decoded.equals(".") || decoded.equals("..")) {
                throw new IllegalArgumentException(SUFFIX_RULE);
            }
        }
        String combined = baseUrl + trimmed;
        java.net.URI before;
        java.net.URI after;
        try {
            before = new java.net.URI(baseUrl);
            after = new java.net.URI(combined);
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException(SUFFIX_RULE);
        }
        if (after.getHost() == null || !after.getHost().equalsIgnoreCase(String.valueOf(before.getHost()))
                || !after.getScheme().equalsIgnoreCase(before.getScheme()) || after.getPort() != before.getPort()
                || after.getRawUserInfo() != null || after.getRawQuery() != null || after.getRawFragment() != null) {
            throw new IllegalArgumentException(SUFFIX_RULE);
        }
        return combined;
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }
}
