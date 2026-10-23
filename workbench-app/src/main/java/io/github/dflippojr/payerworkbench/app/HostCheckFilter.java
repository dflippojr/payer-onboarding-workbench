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
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Refuses a request whose {@code Host} this workbench doesn't answer to, before any other filter (#201).
 *
 * <p>The loopback bind keeps other machines out, but not a web page the user visits: with DNS rebinding
 * the page's own name resolves to 127.0.0.1, so its same-origin requests reach the API with that name in
 * {@code Host}. The allowed names are {@code localhost}, {@code 127.0.0.1}, {@code [::1]}, the
 * {@code server.address} literal unless it is a wildcard, and {@code workbench.allowed-hosts}; the single
 * value {@code *} turns the check off. The port is ignored and case doesn't matter. A configured IPv6
 * address is compared in the compressed form a browser sends, however it was written.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class HostCheckFilter extends OncePerRequestFilter {

    public static final String SETTING = "workbench.allowed-hosts";

    private static final byte[] REFUSAL = ("""
            {"type":"about:blank","title":"Forbidden","status":403,"detail":"This workbench answers only to \
            localhost, 127.0.0.1, [::1], its server.address and the names in %s, so that a web page \
            cannot reach it through DNS rebinding. Add the name you use to %s."}""")
            .formatted(SETTING, SETTING).getBytes(StandardCharsets.UTF_8);

    /** A host name or IPv4 address, or an IPv6 address in brackets, then an optional port. */
    private static final Pattern ENTRY = Pattern.compile(
            "(\\[[0-9a-f:.]++]|[a-z0-9-]++(?:\\.[a-z0-9-]++)*+)(?::([0-9]{1,5}))?", Pattern.CASE_INSENSITIVE);

    /** Lower-case host names without a port; {@code null} when the check is off. */
    private final Set<String> allowed;

    public HostCheckFilter(@Value("${server.address:}") String serverAddress,
                    @Value("${" + SETTING + ":}") String allowedHosts) {
        this.allowed = allowedHosts(serverAddress, allowedHosts);
    }

    /** The names a request may carry in {@code Host}, or {@code null} for {@code *}. */
    static Set<String> allowedHosts(String serverAddress, String allowedHosts) {
        Set<String> configured = new LinkedHashSet<>();
        if (!allowedHosts.isBlank()) {
            // -1 keeps a trailing empty entry, so "a.test," fails like "a.test,,b.test".
            for (String entry : allowedHosts.split(",", -1)) {
                configured.add(entry.strip().equals("*") ? "*" : configuredName(entry.strip()));
            }
        }
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

    /**
     * A {@code workbench.allowed-hosts} entry as it will appear in {@code Host}: a host name, an IPv4 address
     * or an IPv6 literal, optionally with a port, which is dropped. Anything else, such as a URL, a path, user
     * info, a wildcard or an empty entry, fails at startup rather than allowing a name nobody meant.
     */
    static String configuredName(String entry) {
        boolean bareIpv6 = !entry.startsWith("[") && entry.indexOf(':') != entry.lastIndexOf(':');
        Matcher matcher = ENTRY.matcher(bareIpv6 ? "[" + entry + "]" : entry);
        if (matcher.matches() && validPort(matcher.group(2))) {
            String name = matcher.group(1);
            if (!name.startsWith("[")) {
                return name.toLowerCase(Locale.ROOT);
            }
            try {
                return ipv6Literal(InetAddress.getByName(name));
            } catch (UnknownHostException e) {
                // Not an IPv6 address after all; refused below.
            }
        }
        throw new IllegalArgumentException(SETTING + ": '" + entry + "' is not a host name, IPv4 address or"
                + " [IPv6 address] with an optional :port. Leave out the scheme, path and user info, list every"
                + " name in full (no wildcards) and separate them with single commas.");
    }

    private static boolean validPort(String port) {
        return port == null || Integer.parseInt(port) >= 1 && Integer.parseInt(port) <= 65535;
    }

    /** {@code server.address} as a browser would put it in {@code Host}; {@code null} if unset or a wildcard. */
    static String boundLiteral(String serverAddress) {
        String address = hostName(serverAddress.strip());
        if (address == null || address.isEmpty() || address.equals("0.0.0.0")) {
            return null;
        }
        if (!address.startsWith("[")) {
            return address;
        }
        try {
            // Bracketed, so a literal and never a lookup.
            InetAddress literal = InetAddress.getByName(address);
            return literal.isAnyLocalAddress() ? null : ipv6Literal(literal);
        } catch (UnknownHostException e) {
            return address;
        }
    }

    /**
     * An IPv6 address the way a browser writes it in {@code Host} (the WHATWG URL serializer, as RFC 5952):
     * lower-case groups without leading zeros, and the first longest run of two or more zero groups as
     * {@code ::}. The JDK turns {@code ::ffff:a.b.c.d} into an IPv4 address, so that one is mapped back.
     */
    static String ipv6Literal(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            byte[] mapped = new byte[16];
            mapped[10] = (byte) 0xff;
            mapped[11] = (byte) 0xff;
            System.arraycopy(bytes, 0, mapped, 12, 4);
            bytes = mapped;
        }
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = (bytes[2 * i] & 0xff) << 8 | bytes[2 * i + 1] & 0xff;
        }
        int runStart = -1;
        int runLength = 1;
        for (int i = 0; i < 8; i++) {
            int end = i;
            while (end < 8 && groups[end] == 0) {
                end++;
            }
            if (end - i > runLength) {
                runStart = i;
                runLength = end - i;
            }
        }
        if (runStart < 0) {
            return "[" + hex(groups, 0, 8) + "]";
        }
        return "[" + hex(groups, 0, runStart) + "::" + hex(groups, runStart + runLength, 8) + "]";
    }

    private static String hex(int[] groups, int from, int to) {
        StringJoiner joined = new StringJoiner(":");
        for (int i = from; i < to; i++) {
            joined.add(Integer.toHexString(groups[i]));
        }
        return joined.toString();
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
