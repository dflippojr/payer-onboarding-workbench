package io.github.dflippojr.payerworkbench.diagnostics;

import io.github.dflippojr.payerworkbench.core.DiagnosticCheck;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code tls.handshake}: TLS (and mutual TLS) connections to the payer succeeded.
 * Classifies handshake failures from the transport error text: the payer's
 * certificate is not trusted, has expired or names another host; the payer
 * requires a client certificate the workbench did not send; the payer does not
 * trust the client certificate; or the two sides share no protocol version.
 */
public final class TlsHandshakeCheck implements DiagnosticCheck {

    public static final String ID = "tls.handshake";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public List<Finding> evaluate(RunObservations obs) {
        boolean mtls = obs.connection().mtlsConfigured();
        Map<String, Finding> failures = new LinkedHashMap<>();
        Set<String> okHosts = new LinkedHashSet<>();
        for (HttpExchange exchange : allExchanges(obs)) {
            String host = host(exchange.url());
            if (exchange.responded()) {
                if (exchange.url().regionMatches(true, 0, "https:", 0, 6)) {
                    okHosts.add(host);
                }
                continue;
            }
            Cause cause = classify(exchange.transportError(), mtls);
            if (cause != null) {
                failures.putIfAbsent(host + "|" + cause.name(), finding(cause, host, exchange, mtls));
            }
        }
        if (!failures.isEmpty()) {
            return List.copyOf(failures.values());
        }
        if (okHosts.isEmpty()) {
            return List.of();
        }
        return List.of(new Finding(ID, Severity.PASS,
                mtls ? "TLS and client certificate accepted" : "TLS handshake succeeded",
                "Encrypted (HTTPS) connections to the payer were established and its certificate was trusted"
                        + (mtls ? ", and the payer accepted the workbench's client certificate (mutual TLS)." : "."),
                "hosts: " + String.join(", ", okHosts), null));
    }

    private static List<HttpExchange> allExchanges(RunObservations obs) {
        List<HttpExchange> all = new ArrayList<>(obs.exchanges());
        if (obs.discovery() != null && !all.contains(obs.discovery())) {
            all.add(obs.discovery());
        }
        obs.hookResponses().forEach(h -> {
            if (!all.contains(h.exchange())) {
                all.add(h.exchange());
            }
        });
        return all;
    }

    enum Cause {
        UNTRUSTED_SERVER_CA,
        SERVER_CERT_EXPIRED,
        HOSTNAME_MISMATCH,
        CLIENT_CERT_MISSING,
        CLIENT_CERT_REJECTED,
        PROTOCOL_MISMATCH,
        OTHER
    }

    /** The likely cause of a transport error, or {@code null} if it is not a TLS failure. */
    static Cause classify(String error, boolean mtlsConfigured) {
        String e = Support.lower(error);
        if (e.isEmpty()) {
            return null;
        }
        if (e.contains("pkix") || e.contains("unable to find valid certification path")
                || e.contains("self-signed") || e.contains("self signed") || e.contains("unable to get local issuer")) {
            return Cause.UNTRUSTED_SERVER_CA;
        }
        if (e.contains("certificateexpired") || e.contains("certificate expired") || e.contains("notafter")
                || e.contains("certificate has expired")) {
            return Cause.SERVER_CERT_EXPIRED;
        }
        if (e.contains("no subject alternative") || e.contains("no name matching")
                || e.contains("doesn't match any of the subject alternative names") || e.contains("hostname mismatch") || e.contains("hostname verification")) {
            return Cause.HOSTNAME_MISMATCH;
        }
        if (e.contains("unknown_ca") || e.contains("certificate_unknown") || e.contains("certificate_revoked")
                || e.contains("unsupported_certificate")) {
            return mtlsConfigured ? Cause.CLIENT_CERT_REJECTED : Cause.CLIENT_CERT_MISSING;
        }
        if (e.contains("certificate_required") || e.contains("bad_certificate")) {
            return mtlsConfigured ? Cause.CLIENT_CERT_REJECTED : Cause.CLIENT_CERT_MISSING;
        }
        if (e.contains("protocol_version") || e.contains("no appropriate protocol")
                || e.contains("no cipher suites in common") || e.contains("insufficient_security")) {
            return Cause.PROTOCOL_MISMATCH;
        }
        if (e.contains("handshake_failure") && !mtlsConfigured) {
            return Cause.CLIENT_CERT_MISSING;
        }
        if (e.contains("ssl") || e.contains("tls") || e.contains("handshake") || e.contains("certificate")) {
            return Cause.OTHER;
        }
        return null;
    }

    private static Finding finding(Cause cause, String host, HttpExchange exchange, boolean mtls) {
        String evidence = Support.describe(exchange) + "\nclient certificate configured: " + (mtls ? "yes" : "no");
        String tls = "The TLS handshake (the step where client and server agree on encryption and check each "
                + "other's certificates before any HTTP is sent) with " + host + " failed";
        return switch (cause) {
            case UNTRUSTED_SERVER_CA -> new Finding(ID, Severity.FAIL, "Payer's TLS certificate is not trusted",
                    tls + " because the payer's certificate was issued by a certificate authority the workbench's "
                            + "trust store does not include, which is common in payer sandboxes with private CAs.",
                    evidence,
                    "Get the payer's CA (or intermediate) certificate from their onboarding team and add it to the "
                            + "trust store the workbench uses; do not disable certificate validation.");
            case SERVER_CERT_EXPIRED -> new Finding(ID, Severity.FAIL, "Payer's TLS certificate has expired",
                    tls + " because the payer's certificate is past its expiry date, so it can no longer prove the "
                            + "server's identity.",
                    evidence,
                    "Tell the payer their certificate for " + host + " has expired; also confirm this machine's "
                            + "clock is correct.");
            case HOSTNAME_MISMATCH -> new Finding(ID, Severity.FAIL, "Payer's TLS certificate names a different host",
                    tls + " because the certificate does not list " + host + " among the names it is valid for.",
                    evidence,
                    "Use the exact hostname the payer published (it must appear in the certificate), not an IP "
                            + "address or internal alias, in the connection record's URLs.");
            case CLIENT_CERT_MISSING -> new Finding(ID, Severity.FAIL, "Payer requires a client certificate (mutual TLS)",
                    tls + ". The payer appears to require mutual TLS, where the client must also present a "
                            + "certificate, and the connection record has no client certificate configured.",
                    evidence,
                    "Obtain a client certificate the payer trusts (usually by sending them a CSR or your CA "
                            + "chain), store it, and set mtlsCredentialRef on the connection record.");
            case CLIENT_CERT_REJECTED -> new Finding(ID, Severity.FAIL, "Payer rejected the client certificate",
                    tls + ". A client certificate was sent for mutual TLS, but the payer did not accept it, usually "
                            + "because it was issued by a CA the payer has not been told to trust, has expired, or "
                            + "is not the certificate registered for this environment.",
                    evidence,
                    "Confirm with the payer which CA and certificate they have registered for this client and "
                            + "environment, and check that mtlsCredentialRef points at that certificate and its key.");
            case PROTOCOL_MISMATCH -> new Finding(ID, Severity.FAIL, "No common TLS version or cipher",
                    tls + " because the two sides share no TLS version or cipher suite; most payers require "
                            + "TLS 1.2 or later.",
                    evidence,
                    "Make sure the workbench's JVM allows TLS 1.2 and 1.3 and has not disabled the payer's cipher "
                            + "suites, and ask the payer which versions their endpoint accepts.");
            case OTHER -> new Finding(ID, Severity.FAIL, "TLS handshake failed",
                    tls + ". The error does not match a known cause.",
                    evidence,
                    "Re-run with -Djavax.net.debug=ssl:handshake to see which side ended the handshake, and share "
                            + "that output (it contains no secrets) with the payer.");
        };
    }

    private static String host(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getHost() == null ? url : uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
        } catch (IllegalArgumentException e) {
            return url;
        }
    }
}
