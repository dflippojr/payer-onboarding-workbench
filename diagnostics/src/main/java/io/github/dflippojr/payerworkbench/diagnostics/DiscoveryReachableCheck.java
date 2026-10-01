package io.github.dflippojr.payerworkbench.diagnostics;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.util.List;
import java.util.Optional;

/**
 * {@code discovery.reachable}: the discovery endpoint answered with HTTP 200 and a
 * JSON document that has a {@code services} array.
 */
public final class DiscoveryReachableCheck implements DiagnosticCheck {

    public static final String ID = "discovery.reachable";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        HttpExchange discovery = obs.discovery();
        if (discovery == null) {
            return List.of();
        }
        String evidence = Support.describe(discovery);
        if (!discovery.responded()) {
            return List.of(fail("Discovery endpoint unreachable",
                    "The workbench could not get any HTTP response from the payer's discovery endpoint "
                            + "(GET .../cds-services, the URL that lists the payer's CDS Hooks services). "
                            + "Without it the client cannot learn which hooks the payer offers.",
                    evidence,
                    "Confirm the base URL in the connection record, that the host resolves and accepts "
                            + "connections from this network (firewall or VPN allow-listing), and see any "
                            + "tls.handshake finding if the error mentions TLS or certificates."));
        }
        if (discovery.status() != 200) {
            return List.of(fail("Discovery returned HTTP " + discovery.status(),
                    "The discovery endpoint answered, but not with HTTP 200 OK, so there is no list of "
                            + "services to read. CDS Hooks requires discovery to return 200 with a JSON body.",
                    evidence, fixForStatus(discovery.status())));
        }
        Optional<JsonNode> json = Support.parseJson(discovery.responseBody());
        if (json.isEmpty()) {
            return List.of(fail("Discovery response is not JSON",
                    "The discovery endpoint returned HTTP 200, but the body is not JSON. This usually means "
                            + "the URL points at a web page, login page or proxy rather than the CDS Hooks "
                            + "service.",
                    evidence,
                    "Open the discovery URL directly and check it returns application/json shaped like "
                            + "{\"services\": [...]}; if it returns HTML, correct the base URL or ask the payer "
                            + "for the CDS Hooks base URL."));
        }
        if (!json.get().path("services").isArray()) {
            return List.of(fail("Discovery JSON has no services array",
                    "The discovery response is JSON but lacks the top-level \"services\" array that the CDS "
                            + "Hooks spec requires, so the client cannot find any hooks.",
                    evidence,
                    "Ask the payer to return {\"services\": [...]} from GET {baseUrl}/cds-services, or check "
                            + "that the base URL is the CDS Hooks root and not another API."));
        }
        return List.of(new Finding(ID, Severity.PASS, "Discovery endpoint reachable",
                "The discovery endpoint returned HTTP 200 with a JSON list of services.",
                discovery.method() + " " + discovery.url() + " -> HTTP 200 in "
                        + discovery.latency().toMillis() + " ms",
                null));
    }

    private static Finding fail(String title, String explanation, String evidence, String fix) {
        return new Finding(ID, Severity.FAIL, title, explanation, evidence, fix);
    }

    private static String fixForStatus(int status) {
        if (status == 404) {
            return "Check the base URL: the workbench requests {baseUrl}/cds-services, so a base URL that "
                    + "already ends in /cds-services, or lacks a path prefix such as /fhir or /r4, gives 404.";
        }
        if (status == 401 || status == 403) {
            return "The payer protects discovery. Confirm whether discovery needs the same credentials as hook "
                    + "calls, and that this client is allow-listed for this environment.";
        }
        if (status >= 500) {
            return "The payer's server failed. Retry later, and send the payer the request time and any "
                    + "correlation id from the response headers.";
        }
        if (status >= 300 && status < 400) {
            return "The payer redirected discovery. Use the final URL (from the Location header) as the base URL; "
                    + "CDS clients do not reliably follow redirects.";
        }
        return "Compare the request with the payer's onboarding guide and correct the base URL or headers.";
    }
}
