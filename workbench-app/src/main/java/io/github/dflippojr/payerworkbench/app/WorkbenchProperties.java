package io.github.dflippojr.payerworkbench.app;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.time.Duration;

/**
 * Settings under {@code workbench.*}.
 *
 * @param slowResponseDelay how long the {@code slow-response} fault holds each response when a run
 *                          doesn't say; the default is past the 10 s latency budget, so it fails.
 *                          A run may ask for up to {@link #maxSlowResponseDelay()}
 * @param latencyWarn       hook latency that is a WARN
 * @param latencyFail       hook latency that is a FAIL (CDS Hooks clients often give up around here)
 * @param requestTimeout    how long the workbench waits for any one HTTP response, body included
 * @param maxRuns           how many runs {@code GET /api/runs/{id}} remembers
 * @param customEndpoints   {@code workbench.custom-endpoints.*}
 * @param audit             {@code workbench.audit.*}: the optional durable audit journal
 * @param maxResponseBytes  the most of any one payer response body the workbench reads (default 4 MiB);
 *                          a longer body fails the call with a finding naming the limit
 * @param maxStoredRunBytes the most the remembered runs may take together, measured as JSON
 *                          (default 32 MiB); past it the oldest are forgotten even under {@code maxRuns}
 * @param maxResponseJsonValues the most JSON values (objects, arrays, strings, numbers, booleans and
 *                          nulls) a payer response body may hold before the workbench refuses to parse
 *                          it (default 100,000); 4 MiB of {@code {}} is 1.4 million objects
 * @param maxConcurrentRuns how many custom-endpoint runs may be in flight at once (default 4); one more
 *                          is refused with 503 rather than queued, because the per-run limits bound
 *                          one run's memory and this bounds how many of them the heap holds together
 */
@ConfigurationProperties("workbench")
public record WorkbenchProperties(
        Duration slowResponseDelay,
        Duration latencyWarn,
        Duration latencyFail,
        Duration requestTimeout,
        Integer maxRuns,
        CustomEndpoints customEndpoints,
        Audit audit,
        Long maxResponseBytes,
        Long maxStoredRunBytes,
        Integer maxResponseJsonValues,
        Integer maxConcurrentRuns
) {
    /** Default {@link #requestTimeout()}: 15 s. */
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(15);

    /**
     * The longest {@code slowResponseDelayMs} a run may ask for: {@link #requestTimeout()} plus 1 s. The
     * workbench gives up on the call at the timeout, so a longer delay only keeps the mock payer sleeping.
     */
    public Duration maxSlowResponseDelay() {
        return requestTimeout.plusSeconds(1);
    }

    /** Default {@link #maxResponseBytes()}: 4 MiB. */
    public static final long DEFAULT_MAX_RESPONSE_BYTES = 4L * 1024 * 1024;

    /** Default {@link #maxStoredRunBytes()}: 32 MiB. */
    public static final long DEFAULT_MAX_STORED_RUN_BYTES = 32L * 1024 * 1024;

    /** Default {@link #maxResponseJsonValues()}. */
    public static final int DEFAULT_MAX_RESPONSE_JSON_VALUES = 100_000;

    /** Default {@link #maxConcurrentRuns()}. */
    public static final int DEFAULT_MAX_CONCURRENT_RUNS = 4;

    /**
     * @param enabled whether {@code POST /api/runs} accepts a {@code customEndpoint}; off by default
     *                because an enabled copy forwards requests to hosts the caller names
     */
    public record CustomEndpoints(Boolean enabled) {
        public CustomEndpoints {
            enabled = enabled != null && enabled;
        }
    }

    /**
     * Durable audit journal; off unless {@code journalDir} is set.
     *
     * @param journalDir    absolute directory outside any checkout, owner-only
     * @param retention     how long closed segments are kept (default 30 days)
     * @param segmentBytes  size at which a segment is closed (default 10 MiB)
     * @param totalBytes    cap on all segments; the oldest closed ones expire first (default 100 MiB)
     * @param operatorLabel optional label for the process in the manifest; never an actor
     */
    public record Audit(String journalDir, Duration retention, Long segmentBytes, Long totalBytes,
                        String operatorLabel) {
        public Audit {
            retention = retention == null ? Duration.ofDays(30) : retention;
            segmentBytes = segmentBytes == null ? 10L * 1024 * 1024 : segmentBytes;
            totalBytes = totalBytes == null ? 100L * 1024 * 1024 : totalBytes;
            journalDir = journalDir == null || journalDir.isBlank() ? null : journalDir;
        }
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns, CustomEndpoints customEndpoints, Audit audit,
                               Long maxResponseBytes, Long maxStoredRunBytes, Integer maxResponseJsonValues) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, customEndpoints, audit,
                maxResponseBytes, maxStoredRunBytes, maxResponseJsonValues, null);
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns, CustomEndpoints customEndpoints, Audit audit,
                               Long maxResponseBytes, Long maxStoredRunBytes) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, customEndpoints, audit,
                maxResponseBytes, maxStoredRunBytes, null);
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns, CustomEndpoints customEndpoints, Audit audit,
                               Long maxResponseBytes) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, customEndpoints, audit,
                maxResponseBytes, null, null);
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns, CustomEndpoints customEndpoints, Audit audit) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, customEndpoints, audit, null, null, null);
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns, CustomEndpoints customEndpoints) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, customEndpoints, null, null, null, null);
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, null, null, null, null, null);
    }

    @ConstructorBinding
    public WorkbenchProperties {
        audit = audit == null ? new Audit(null, null, null, null, null) : audit;
        customEndpoints = customEndpoints == null ? new CustomEndpoints(false) : customEndpoints;
        slowResponseDelay = slowResponseDelay == null ? Duration.ofSeconds(11) : slowResponseDelay;
        if (slowResponseDelay.isNegative()) {
            throw new IllegalArgumentException("workbench.slow-response-delay must not be negative");
        }
        latencyWarn = latencyWarn == null ? Duration.ofSeconds(5) : latencyWarn;
        if (latencyWarn.isNegative()) {
            throw new IllegalArgumentException("workbench.latency-warn must not be negative");
        }
        latencyFail = latencyFail == null ? Duration.ofSeconds(10) : latencyFail;
        if (latencyFail.isNegative()) {
            throw new IllegalArgumentException("workbench.latency-fail must not be negative");
        }
        requestTimeout = requestTimeout == null ? DEFAULT_REQUEST_TIMEOUT : requestTimeout;
        if (!requestTimeout.isPositive()) {
            throw new IllegalArgumentException("workbench.request-timeout must be positive");
        }
        maxRuns = maxRuns == null ? 200 : maxRuns;
        if (maxRuns <= 0) {
            throw new IllegalArgumentException("workbench.max-runs must be positive");
        }
        maxResponseBytes = maxResponseBytes == null ? DEFAULT_MAX_RESPONSE_BYTES : maxResponseBytes;
        if (maxResponseBytes <= 0 || maxResponseBytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("workbench.max-response-bytes must be between 1 and " + Integer.MAX_VALUE);
        }
        maxStoredRunBytes = maxStoredRunBytes == null ? DEFAULT_MAX_STORED_RUN_BYTES : maxStoredRunBytes;
        if (maxStoredRunBytes <= 0) {
            throw new IllegalArgumentException("workbench.max-stored-run-bytes must be positive");
        }
        maxResponseJsonValues = maxResponseJsonValues == null ? DEFAULT_MAX_RESPONSE_JSON_VALUES : maxResponseJsonValues;
        if (maxResponseJsonValues <= 0) {
            throw new IllegalArgumentException("workbench.max-response-json-values must be positive");
        }
        maxConcurrentRuns = maxConcurrentRuns == null ? DEFAULT_MAX_CONCURRENT_RUNS : maxConcurrentRuns;
        if (maxConcurrentRuns <= 0) {
            throw new IllegalArgumentException("workbench.max-concurrent-runs must be positive");
        }
    }
}
