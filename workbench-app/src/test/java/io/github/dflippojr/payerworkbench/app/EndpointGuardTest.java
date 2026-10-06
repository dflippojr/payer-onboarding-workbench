package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Destination rules with a fake resolver, so no test touches DNS. */
class EndpointGuardTest {

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static EndpointGuard guard(Map<String, String> dns) {
        return new EndpointGuard(host -> {
            String answer = dns.get(host);
            return answer != null ? new InetAddress[] {ip(answer)} : InetAddress.getAllByName(host);
        });
    }

    @Test
    void publicHttpsIsApproved() {
        URI uri = guard(Map.of("payer.example.com", "93.184.216.34")).approve("Base URL", "https://payer.example.com/r4");
        assertEquals("payer.example.com", uri.getHost());
    }

    @Test
    void aPublicNameThatResolvesToAnInternalAddressIsRefused() {
        EndpointGuard guard = guard(Map.of("evil.example.com", "10.1.2.3", "meta.example.com", "169.254.169.254",
                "local.example.com", "127.0.0.1"));
        for (String host : new String[] {"evil.example.com", "meta.example.com", "local.example.com"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> guard.approve("Base URL", "https://" + host + "/"));
            assertTrue(e.getMessage().contains("resolves to"), e.getMessage());
        }
        // A name that resolves to loopback does not earn plain http either.
        assertThrows(IllegalArgumentException.class, () -> guard.approve("Base URL", "http://local.example.com/"));
    }

    @Test
    void loopbackAllowsHttp() {
        EndpointGuard guard = guard(Map.of());
        guard.approve("Base URL", "http://127.0.0.1:18090/r4");
        guard.approve("Base URL", "http://localhost:18090/r4");
        guard.approve("Base URL", "http://[::1]:18090/r4");
    }

    @Test
    void unresolvableHostIsRefusedWithAClearMessage() {
        EndpointGuard guard = new EndpointGuard(host -> {
            throw new UnknownHostException(host);
        });
        assertTrue(assertThrows(IllegalArgumentException.class, () -> guard.approve("Base URL", "https://nope.example/"))
                .getMessage().contains("could not be resolved"));
    }

    @Test
    void addressClassification() {
        for (String blocked : new String[] {"10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.0.1", "127.0.0.1",
                "169.254.169.254", "100.64.0.1", "100.100.100.200", "0.0.0.0", "224.0.0.1", "240.0.0.1",
                "168.63.129.16", "198.18.0.1", "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "64:ff9b::a00:1"}) {
            assertFalse(EndpointGuard.isPublic(ip(blocked)), blocked);
        }
        for (String open : new String[] {"8.8.8.8", "93.184.216.34", "172.32.0.1", "100.128.0.1", "2606:4700::1111"}) {
            assertTrue(EndpointGuard.isPublic(ip(open)), open);
        }
    }

    @Test
    void wrappedClientRefusesUnapprovedHostsAndChangedAnswers() throws Exception {
        String[] answer = {"93.184.216.34"};
        EndpointGuard guard = new EndpointGuard(host -> new InetAddress[] {ip(answer[0])});
        guard.approve("Base URL", "https://payer.example.com/r4");
        HttpClient client = guard.wrap(HttpClient.newHttpClient());

        IOException other = assertThrows(IOException.class, () -> client.send(
                HttpRequest.newBuilder(URI.create("https://other.example.com/")).build(),
                java.net.http.HttpResponse.BodyHandlers.discarding()));
        assertTrue(other.getMessage().contains("not the approved payer endpoint"));

        answer[0] = "10.0.0.9"; // DNS rebinding after approval
        IOException rebound = assertThrows(IOException.class, () -> client.send(
                HttpRequest.newBuilder(URI.create("https://payer.example.com/r4")).build(),
                java.net.http.HttpResponse.BodyHandlers.discarding()));
        assertTrue(rebound.getMessage().contains("DNS answer changed"));
    }
}
