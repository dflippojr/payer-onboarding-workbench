package io.github.dflippojr.payerworkbench.app;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Destination rules for a user-supplied payer endpoint (server-side request forgery
 * defence). {@code https} may go to public hosts only; {@code http} only to a loopback
 * host written as {@code localhost} or a loopback IP literal. Private, link-local,
 * unique-local, carrier-grade NAT and cloud-metadata addresses are rejected for every
 * other host.
 *
 * <p>A hostname is resolved once, when a URL is {@linkplain #approve approved}, and every
 * request the run later sends is checked against that answer: {@link #wrap} re-resolves
 * the host and refuses a request whose answer no longer matches, so a DNS rebind during a
 * run cannot move the call to an internal address. The JDK client does its own lookup when
 * it connects, so a rebind inside that window is narrowed rather than impossible; see the
 * README.
 */
final class EndpointGuard {

    /** Looks a host up; replaceable so tests need no DNS. */
    @FunctionalInterface
    interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final Set<String> METADATA_HOSTS = Set.of("metadata", "metadata.google.internal", "instance-data");

    private final Resolver resolver;
    private final Map<String, Set<InetAddress>> approved = new ConcurrentHashMap<>();

    EndpointGuard() {
        this(InetAddress::getAllByName);
    }

    EndpointGuard(Resolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Checks {@code url} and remembers the addresses its host resolved to.
     *
     * @param label what the URL is for, used in the message ("Base URL", "Token endpoint")
     * @throws IllegalArgumentException with a message fit to show the user
     */
    URI approve(String label, String url) {
        URI uri = parse(label, url);
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        String host = hostOf(uri);
        boolean loopbackName = isLoopbackName(host);
        if (scheme.equals("http") && !loopbackName) {
            throw new IllegalArgumentException(label + " uses plain http to " + host + ". Plain http is only allowed to "
                    + "loopback hosts (localhost, 127.0.0.1, [::1]); use https for any other host.");
        }
        if (METADATA_HOSTS.contains(host)) {
            throw new IllegalArgumentException(label + " points at " + host + ", a cloud metadata address, which "
                    + "custom endpoints may not reach.");
        }
        Set<InetAddress> addresses = lookup(label, host);
        for (InetAddress address : addresses) {
            if (loopbackName ? !address.isLoopbackAddress() : !isPublic(address)) {
                throw new IllegalArgumentException(label + " host " + host + " resolves to " + address.getHostAddress()
                        + (loopbackName ? ", which is not a loopback address."
                        : ", a private, loopback, link-local or metadata address. Custom endpoints must be public "
                                + "hosts over https, or loopback (localhost, 127.0.0.1, [::1])."));
            }
        }
        approved.put(host, addresses);
        return uri;
    }

    /** {@code delegate}, but every request must go to a host this guard approved, at the address it approved. */
    HttpClient wrap(HttpClient delegate) {
        return new ForwardingHttpClient(delegate) {
            @Override
            protected HttpRequest prepare(HttpRequest request) throws IOException {
                String host = hostOf(request.uri());
                Set<InetAddress> pinned = approved.get(host);
                if (pinned == null) {
                    throw new IOException("Refusing to call " + host + ": it is not the approved payer endpoint");
                }
                Set<InetAddress> now;
                try {
                    now = Set.copyOf(Arrays.asList(resolver.resolve(host)));
                } catch (UnknownHostException e) {
                    throw new IOException("Could not resolve " + host, e);
                }
                if (!pinned.containsAll(now)) {
                    throw new IOException("Refusing to call " + host + ": its DNS answer changed during the run");
                }
                return request;
            }
        };
    }

    private static URI parse(String label, String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(label + " is not a valid URL");
        }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))) {
            throw new IllegalArgumentException(label + " must start with https:// (or http:// to a loopback host)");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException(label + " has no host");
        }
        if (uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException(label + " must not contain user info, a query or a fragment; "
                    + "credentials go in the credential field");
        }
        return uri;
    }

    private static String hostOf(URI uri) {
        return uri.getHost().toLowerCase(Locale.ROOT);
    }

    private Set<InetAddress> lookup(String label, String host) {
        try {
            InetAddress[] all = resolver.resolve(host);
            if (all.length == 0) {
                throw new UnknownHostException(host);
            }
            return Set.copyOf(List.of(all));
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(label + " host " + host + " could not be resolved");
        }
    }

    /** {@code localhost} or an IP literal in the loopback range; never a name that merely resolves there. */
    static boolean isLoopbackName(String host) {
        if (host.equals("localhost")) {
            return true;
        }
        boolean literal = IPV4_LITERAL.matcher(host).matches() || host.startsWith("[");
        if (!literal) {
            return false;
        }
        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    static boolean isPublic(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return false;
        }
        byte[] b = address.getAddress();
        if (b.length == 4) {
            int a = b[0] & 0xff;
            int c = b[1] & 0xff;
            return !(a == 0
                    || a == 100 && c >= 64 && c <= 127           // carrier-grade NAT, incl. 100.100.100.200
                    || a == 192 && c == 0 && (b[2] & 0xff) == 0  // IETF protocol assignments
                    || a == 198 && (c == 18 || c == 19)          // benchmarking
                    || a >= 240                                  // reserved and broadcast
                    || a == 168 && c == 63 && (b[2] & 0xff) == 129 && (b[3] & 0xff) == 16); // Azure wire server
        }
        int first = b[0] & 0xff;
        boolean uniqueLocal = (first & 0xfe) == 0xfc;
        boolean nat64 = first == 0x00 && b[1] == 0x64 && (b[2] & 0xff) == 0xff && b[3] == (byte) 0x9b;
        return !(uniqueLocal || nat64);
    }
}
