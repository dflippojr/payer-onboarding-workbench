package io.github.dflippojr.payerworkbench.app;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

import java.time.Duration;

/**
 * Settings under {@code workbench.*}.
 *
 * @param slowResponseDelay how long the {@code slow-response} fault holds each response when a run
 *                          doesn't say; the default is past the 10 s latency budget, so it fails
 * @param latencyWarn       hook latency that is a WARN
 * @param latencyFail       hook latency that is a FAIL (CDS Hooks clients often give up around here)
 * @param requestTimeout    how long the workbench waits for any one HTTP response
 * @param maxRuns           how many runs {@code GET /api/runs/{id}} remembers
 * @param customEndpoints   {@code workbench.custom-endpoints.*}
 */
@ConfigurationProperties("workbench")
public record WorkbenchProperties(
        Duration slowResponseDelay,
        Duration latencyWarn,
        Duration latencyFail,
        Duration requestTimeout,
        Integer maxRuns,
        CustomEndpoints customEndpoints
) {
    /**
     * @param enabled whether {@code POST /api/runs} accepts a {@code customEndpoint}; off by default
     *                because an enabled copy forwards requests to hosts the caller names
     */
    public record CustomEndpoints(Boolean enabled) {
        public CustomEndpoints {
            enabled = enabled != null && enabled;
        }
    }

    public WorkbenchProperties(Duration slowResponseDelay, Duration latencyWarn, Duration latencyFail,
                               Duration requestTimeout, Integer maxRuns) {
        this(slowResponseDelay, latencyWarn, latencyFail, requestTimeout, maxRuns, null);
    }

    @ConstructorBinding
    public WorkbenchProperties {
        customEndpoints = customEndpoints == null ? new CustomEndpoints(false) : customEndpoints;
        slowResponseDelay = slowResponseDelay == null ? Duration.ofSeconds(11) : slowResponseDelay;
        latencyWarn = latencyWarn == null ? Duration.ofSeconds(5) : latencyWarn;
        latencyFail = latencyFail == null ? Duration.ofSeconds(10) : latencyFail;
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(15) : requestTimeout;
        maxRuns = maxRuns == null ? 200 : maxRuns;
    }
}
