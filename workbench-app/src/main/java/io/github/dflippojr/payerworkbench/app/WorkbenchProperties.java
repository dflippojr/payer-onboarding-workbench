package io.github.dflippojr.payerworkbench.app;

import org.springframework.boot.context.properties.ConfigurationProperties;

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
 */
@ConfigurationProperties("workbench")
public record WorkbenchProperties(
        Duration slowResponseDelay,
        Duration latencyWarn,
        Duration latencyFail,
        Duration requestTimeout,
        Integer maxRuns
) {
    public WorkbenchProperties {
        slowResponseDelay = slowResponseDelay == null ? Duration.ofSeconds(11) : slowResponseDelay;
        latencyWarn = latencyWarn == null ? Duration.ofSeconds(5) : latencyWarn;
        latencyFail = latencyFail == null ? Duration.ofSeconds(10) : latencyFail;
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(15) : requestTimeout;
        maxRuns = maxRuns == null ? 200 : maxRuns;
    }
}
