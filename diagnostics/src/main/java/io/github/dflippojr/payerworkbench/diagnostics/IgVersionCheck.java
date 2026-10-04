package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code ig.version}: the CRD implementation guide version the payer reports
 * matches the connection record's {@code igVersion}.
 *
 * <p>CDS Hooks has no standard field for this, so the payer's version is read from,
 * in order: an {@code extension} entry in the discovery document (top level or per
 * service) whose key contains {@code igVersion}, {@code ig-version} or
 * {@code ig_version}; then a versioned Da Vinci CRD canonical URL
 * ({@code http://hl7.org/fhir/us/davinci-crd/...|2.0.1}) in a hook response.
 */
public final class IgVersionCheck implements DiagnosticCheck {

    public static final String CHECK_ID = "ig.version";

    private static final Pattern VERSION_KEY = Pattern.compile("(?i)ig[-_.]?version");
    private static final Pattern VERSIONED_CANONICAL = Pattern.compile(
            "hl7\\.org/fhir/us/davinci-crd/[^\"|\\s]*\\|([0-9][0-9A-Za-z.\\-]*)");

    @Override
    public String id() {
        return CHECK_ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        Optional<Observed> observed = fromDiscovery(obs).or(() -> fromHookResponses(obs));
        String expected = obs.connection().igVersion();
        if (observed.isEmpty()) {
            if (obs.discovery() == null || !Support.isSuccess(obs.discovery().status())) {
                return List.of();
            }
            return List.of(new Finding(CHECK_ID, Severity.INFO, "Payer does not report its CRD IG version",
                    "Neither discovery nor the hook responses say which version of the CRD implementation guide "
                            + "(the Da Vinci spec that defines request and response shapes) the payer follows, so "
                            + "the workbench cannot confirm it matches " + (expected == null ? "the connection record"
                            : "the connection record's " + expected) + ".",
                    null,
                    "Confirm the CRD version with the payer's onboarding contact and record it as igVersion on "
                            + "the connection record."));
        }
        Observed o = observed.get();
        String evidence = "payer: " + o.version() + " (from " + o.source() + "); connection record igVersion: "
                + (expected == null ? "(not set)" : expected);
        if (expected == null || expected.isBlank()) {
            return List.of(new Finding(CHECK_ID, Severity.INFO, "Connection record has no igVersion",
                    "The payer reports CRD implementation guide version " + o.version() + ", but the connection "
                            + "record does not say which version this integration targets, so a later change on "
                            + "either side would go unnoticed.",
                    evidence, "Set igVersion to " + o.version() + " on the connection record."));
        }
        String want = normalize(expected);
        String got = normalize(o.version());
        if (want.equals(got)) {
            return List.of(new Finding(CHECK_ID, Severity.PASS, "CRD IG version matches (" + o.version() + ")",
                    "The payer follows the CRD implementation guide version the connection record expects.",
                    evidence, null));
        }
        boolean majorDiffers = !major(want).equals(major(got));
        return List.of(new Finding(CHECK_ID, majorDiffers ? Severity.FAIL : Severity.WARN,
                "CRD IG version mismatch: payer " + o.version() + ", record " + expected,
                "The payer follows a different version of the CRD implementation guide (the Da Vinci spec that "
                        + "defines request and response shapes) than the connection record expects. "
                        + (majorDiffers
                                ? "Major versions differ, so fields and response formats are likely incompatible."
                                : "Minor or patch versions differ, so some fields or code systems may have changed."),
                evidence,
                "Confirm with the payer which version they will run in production; then either update the "
                        + "connection record's igVersion to " + o.version() + " and re-test, or ask the payer for an "
                        + "endpoint on " + expected + "."));
    }

    private static Optional<Observed> fromDiscovery(RunObservations obs) {
        if (obs.discovery() == null || obs.discovery().status() != 200) {
            return Optional.empty();
        }
        Optional<JsonNode> json = Support.parseJson(obs.discovery().responseBody());
        if (json.isEmpty()) {
            return Optional.empty();
        }
        Optional<Observed> top = versionIn(json.get().path("extension"), "discovery extension");
        if (top.isPresent()) {
            return top;
        }
        for (JsonNode service : json.get().path("services")) {
            Optional<Observed> v = versionIn(service.path("extension"),
                    "discovery extension on service " + service.path("id").asText("(no id)"));
            if (v.isPresent()) {
                return v;
            }
        }
        return Optional.empty();
    }

    private static Optional<Observed> versionIn(JsonNode extension, String source) {
        for (Map.Entry<String, JsonNode> e : extension.properties()) {
            if (VERSION_KEY.matcher(e.getKey()).find() && e.getValue().isTextual()
                    && !e.getValue().asText().isBlank()) {
                return Optional.of(new Observed(e.getValue().asText().strip(), source + " \"" + e.getKey() + "\""));
            }
        }
        return Optional.empty();
    }

    private static Optional<Observed> fromHookResponses(RunObservations obs) {
        for (HookResponse hook : obs.hookResponses()) {
            String body = hook.exchange().responseBody();
            if (body == null) {
                continue;
            }
            Matcher m = VERSIONED_CANONICAL.matcher(body);
            if (m.find()) {
                return Optional.of(new Observed(m.group(1), "versioned profile in " + hook.serviceId() + " response"));
            }
        }
        return Optional.empty();
    }

    private static String normalize(String version) {
        String v = version.strip();
        return v.startsWith("v") || v.startsWith("V") ? v.substring(1) : v;
    }

    private static String major(String version) {
        int dot = version.indexOf('.');
        return dot < 0 ? version : version.substring(0, dot);
    }

    private record Observed(String version, String source) {
    }
}
