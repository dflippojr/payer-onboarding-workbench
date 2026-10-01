package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * {@code perf.latency}: each hook call finished within budget. Over the warn
 * budget (default 5 s) is a WARN; over the fail budget (default 10 s, where CDS
 * Hooks clients often time out) or a timed-out call is a FAIL.
 */
public final class LatencyCheck implements DiagnosticCheck {

    public static final String ID = "perf.latency";

    private static final Pattern TIMEOUT = Pattern.compile("(?i)timed? ?out|timeout");

    private final Duration warn;
    private final Duration fail;

    public LatencyCheck(Duration warn, Duration fail) {
        this.warn = Objects.requireNonNull(warn, "warn");
        this.fail = Objects.requireNonNull(fail, "fail");
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        List<Finding> findings = new ArrayList<>();
        Duration slowest = Duration.ZERO;
        int measured = 0;
        for (HookResponse hook : obs.hookResponses()) {
            HttpExchange exchange = hook.exchange();
            Duration latency = exchange.latency();
            boolean timedOut = !exchange.responded() && exchange.transportError() != null
                    && TIMEOUT.matcher(exchange.transportError()).find();
            if (!exchange.responded() && !timedOut) {
                continue;
            }
            measured++;
            if (latency.compareTo(slowest) > 0) {
                slowest = latency;
            }
            String label = hook.serviceId() + " (" + (hook.hook() == null ? "hook" : hook.hook()) + ")";
            if (timedOut) {
                findings.add(new Finding(ID, Severity.FAIL, "Hook call to " + label + " timed out",
                        "The payer did not answer the hook call before the client gave up after "
                                + latency.toMillis() + " ms. A CDS Hooks call runs while the clinician waits, so a "
                                + "timeout means no coverage guidance is shown at all.",
                        Support.describe(exchange),
                        "Re-run to see if it is intermittent, and send the payer the request time; if their "
                                + "service is slow for this request type, ask what latency they commit to."));
            } else if (latency.compareTo(fail) > 0) {
                findings.add(new Finding(ID, Severity.FAIL, "Hook call to " + label + " took " + seconds(latency),
                        "The call took longer than " + seconds(fail) + ". CDS Hooks calls run while the clinician "
                                + "waits, and many EHRs abandon them around 10 seconds, so in production this "
                                + "response would usually be thrown away.",
                        Support.describe(exchange),
                        "Send the payer the timing and the request; ask whether prefetch data was missing (which "
                                + "makes them query back) and what latency they commit to."));
            } else if (latency.compareTo(warn) > 0) {
                findings.add(new Finding(ID, Severity.WARN, "Hook call to " + label + " took " + seconds(latency),
                        "The call took longer than the " + seconds(warn) + " budget. It completed, but slow hook "
                                + "calls delay the clinician's workflow and get close to the point where EHRs "
                                + "give up (often about 10 seconds).",
                        Support.describe(exchange),
                        "Check that every prefetch key the payer asks for is supplied so they need not query back, "
                                + "and raise the latency with the payer if it persists."));
            }
        }
        if (findings.isEmpty() && measured > 0) {
            findings.add(new Finding(ID, Severity.PASS, "Hook latency within budget",
                    "Every hook call completed within " + seconds(warn) + ".",
                    measured + " call(s); slowest " + slowest.toMillis() + " ms", null));
        }
        return findings;
    }

    private static String seconds(Duration d) {
        return String.format(Locale.ROOT, "%.1f s", d.toMillis() / 1000.0);
    }
}
