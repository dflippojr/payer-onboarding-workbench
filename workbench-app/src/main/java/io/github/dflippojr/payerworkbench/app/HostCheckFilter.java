package io.github.dflippojr.payerworkbench.app;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Refuses a request whose {@code Host} this workbench doesn't answer to, before any other filter (#201).
 *
 * <p>The loopback bind keeps other machines out, but not a web page the user visits: with DNS rebinding
 * the page's own name resolves to 127.0.0.1, so its same-origin requests reach the API with that name in
 * {@code Host}. The allowed names are {@code localhost}, {@code 127.0.0.1}, {@code [::1]}, the
 * {@code server.address} literal unless it is a wildcard, and {@code workbench.allowed-hosts}; the single
 * value {@code *} turns the check off. The port is ignored and case doesn't matter.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class HostCheckFilter extends OncePerRequestFilter {

    static final String SETTING = "workbench.allowed-hosts";

    private static final byte[] REFUSAL = ("""
            {"type":"about:blank","title":"Forbidden","status":403,"detail":"This workbench answers only to \
            localhost, 127.0.0.1, [::1], its server.address and the names in %s, so that a web page \
            cannot reach it through DNS rebinding. Add the name you use to %s."}""")
            .formatted(SETTING, SETTING).getBytes(StandardCharsets.UTF_8);

    /** Lower-case host names without a port; {@code null} when the check is off. */
    private final Set<String> allowed;

    HostCheckFilter(@Value("${server.address:}") String serverAddress,
                    @Value("${" + SETTING + ":}") String allowedHosts) {
        this.allowed = allowedHosts(serverAddress, allowedHosts);
    }

    /** The names a request may carry in {@code Host}, or {@code null} for {@code *}. */
    static Set<String> allowedHosts(String serverAddress, String allowedHosts) {
        Set<String> configured = new LinkedHashSet<>();
        Arrays.stream(allowedHosts.split(",")).map(String::strip).filter(name -> !name.isEmpty())
                .forEach(name -> configured.add(name.equals("*") ? name : hostName(name)));
        if (configured.contains("*")) {
            if (configured.size() > 1) {
                throw new IllegalArgumentException(SETTING + ": * turns the Host check off and can't be listed with names");
            }
            return null;
        }
        Set<String> names = new LinkedHashSet<>(Set.of("localhost", "127.0.0.1", "[::1]"));
        String bound = boundLiteral(serverAddress);
        if (bound != null) {
            names.add(bound);
        }
        names.addAll(configured);
        return Set.copyOf(names);
    }

    /** {@code server.address} as a browser would put it in {@code Host}; {@code null} if unset or a wildcard. */
    static String boundLiteral(String serverAddress) {
        String address = hostName(serverAddress.strip());
        if (address == null || address.isEmpty() || address.equals("0.0.0.0")) {
            return null;
        }
        String bare = address.startsWith("[") ? address.substring(1, address.length() - 1) : address;
        if (!bare.contains(":")) {
            return address;
        }
        try {
            // An IPv6 literal, so no lookup happens.
            return InetAddress.getByName(bare).isAnyLocalAddress() ? null : "[" + bare + "]";
        } catch (UnknownHostException e) {
            return "[" + bare + "]";
        }
    }

    /** The name in a {@code Host} value, lower case and without the port; {@code null} for none. */
    static String hostName(String host) {
        if (host == null) {
            return null;
        }
        String name;
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            if (end < 0) {
                return null;
            }
            name = host.substring(0, end + 1);
        } else if (host.indexOf(':') != host.lastIndexOf(':')) {
            // A bare IPv6 literal, as server.address may be written.
            name = "[" + host + "]";
        } else {
            int colon = host.indexOf(':');
            name = colon < 0 ? host : host.substring(0, colon);
        }
        return name.toLowerCase(Locale.ROOT);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String host = hostName(request.getHeader("Host"));
        if (allowed == null || host != null && allowed.contains(host)) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setContentLength(REFUSAL.length);
        response.getOutputStream().write(REFUSAL);
    }
}
