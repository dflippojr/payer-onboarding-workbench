package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Which {@code Host} names {@link HostCheckFilter} lets through (#201). */
class HostCheckFilterTest {

    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "[::1]");

    @ParameterizedTest
    @ValueSource(strings = {"", "127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0"})
    void loopbackOrWildcardBindAllowsOnlyTheLoopbackNames(String serverAddress) {
        assertEquals(LOOPBACK, HostCheckFilter.allowedHosts(serverAddress, ""));
    }

    @Test
    void aSpecificBindAddsItsLiteral() {
        assertTrue(HostCheckFilter.allowedHosts("192.168.1.5", "").contains("192.168.1.5"));
        assertTrue(HostCheckFilter.allowedHosts("Workbench.LAN", "").contains("workbench.lan"));
        assertTrue(HostCheckFilter.allowedHosts("FE80::1", "").contains("[fe80::1]"));
        assertTrue(HostCheckFilter.allowedHosts("[fd00::5]", "").contains("[fd00::5]"));
        assertTrue(HostCheckFilter.allowedHosts("192.168.1.5", "").containsAll(LOOPBACK));
    }

    @Test
    void allowedHostsAddsNamesWithoutTheirPorts() {
        assertEquals(Set.of("localhost", "127.0.0.1", "[::1]", "a.test", "b.test", "[fd00::2]"),
                HostCheckFilter.allowedHosts("127.0.0.1", " a.test , B.Test:8080 , [FD00::2]:80"));
    }

    @Test
    void anIpv6LiteralIsComparedInTheFormABrowserSends() {
        assertTrue(HostCheckFilter.allowedHosts("2001:db8:0:0::5", "").contains("[2001:db8::5]"));
        assertTrue(HostCheckFilter.allowedHosts("[2001:0DB8:0000:0:0:0:0:5]", "").contains("[2001:db8::5]"));
        assertTrue(HostCheckFilter.allowedHosts("fd00:0:0:1:0:0:0:5", "").contains("[fd00:0:0:1::5]"));
        assertTrue(HostCheckFilter.allowedHosts("2001:0:0:1:0:0:1:1", "").contains("[2001::1:0:0:1:1]"));
        assertTrue(HostCheckFilter.allowedHosts("2001:db8:0:1:0:1:0:1", "").contains("[2001:db8:0:1:0:1:0:1]"));
        assertTrue(HostCheckFilter.allowedHosts("0:0:0:0:0:0:0:1", "").contains("[::1]"));
        assertTrue(HostCheckFilter.allowedHosts("127.0.0.1", "[2001:DB8:0:0::5]:80").contains("[2001:db8::5]"));
        assertTrue(HostCheckFilter.allowedHosts("127.0.0.1", "2001:DB8:0:0::5").contains("[2001:db8::5]"));
    }

    @Test
    void starAloneTurnsTheCheckOff() {
        assertNull(HostCheckFilter.allowedHosts("127.0.0.1", "*"));
        assertNull(HostCheckFilter.allowedHosts("127.0.0.1", " * "));
        var e = assertThrows(IllegalArgumentException.class, () -> HostCheckFilter.allowedHosts("127.0.0.1", "*,a.test"));
        assertTrue(e.getMessage().contains(HostCheckFilter.SETTING), e.getMessage());
    }

    @Test
    void anEntryWithoutAHostNameFailsAtStartup() {
        var e = assertThrows(IllegalArgumentException.class, () -> HostCheckFilter.allowedHosts("127.0.0.1", "a.test,[::1"));
        assertTrue(e.getMessage().contains(HostCheckFilter.SETTING), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://workbench.test", "https://workbench.test", "HTTP://workbench.test:8080",
            "workbench.test/", "workbench.test/api", "user@workbench.test", "localhost@attacker.example",
            "*.workbench.test", "work*bench.test", "a.test,,b.test", "a.test,", ",a.test", " , ",
            "work bench.test", "workbench.test\tx", "workbench_test", "workbench.test.", ".workbench.test",
            "workbench..test", "workbench.test:", "workbench.test:http", "workbench.test:99999",
            "workbench.test:80:80", "[::1]x", "[::1]:", "[]", "[zz::1]", "[fe80::1%eth0]", "[127.0.0.1]",
            "[::1]:80:80", "workbench.test?x", "workbench.test#x"})
    void anEntryThatIsNotAHostNameOrIpLiteralFailsAtStartup(String allowedHosts) {
        var e = assertThrows(IllegalArgumentException.class, () -> HostCheckFilter.allowedHosts("127.0.0.1", allowedHosts));
        assertTrue(e.getMessage().contains(HostCheckFilter.SETTING), e.getMessage());
    }

    @Test
    void aUrlShapedEntryStopsTheApplicationFromStarting() {
        new ApplicationContextRunner()
                .withBean(HostCheckFilter.class)
                .withPropertyValues(HostCheckFilter.SETTING + "=http://workbench.test")
                .run(context -> {
                    assertNotNull(context.getStartupFailure(), "started with a URL in " + HostCheckFilter.SETTING);
                    Throwable cause = context.getStartupFailure();
                    while (cause.getCause() != null) {
                        cause = cause.getCause();
                    }
                    assertTrue(cause.getMessage().contains("'http://workbench.test'"), cause.getMessage());
                });
    }

    @Test
    void hostNameDropsThePortAndCase() {
        assertEquals("localhost", HostCheckFilter.hostName("LocalHost:8080"));
        assertEquals("[::1]", HostCheckFilter.hostName("[::1]:8080"));
        assertEquals("127.0.0.1", HostCheckFilter.hostName("127.0.0.1"));
        assertNull(HostCheckFilter.hostName("[::1"));
        assertNull(HostCheckFilter.hostName(null));
    }

    @Test
    void refusalIsAProblemDetailNamingTheSetting() throws Exception {
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();
        new HostCheckFilter("127.0.0.1", "").doFilter(request("attacker.example:8080"), response, chain);
        assertEquals(403, response.getStatus());
        assertEquals("application/problem+json", response.getContentType());
        assertTrue(response.getContentAsString().contains("\"status\":403"), response.getContentAsString());
        assertTrue(response.getContentAsString().contains(HostCheckFilter.SETTING), response.getContentAsString());
        assertNull(chain.getRequest(), "the refused request went down the chain");
    }

    @Test
    void requestWithoutHostIsRefused() throws Exception {
        var response = new MockHttpServletResponse();
        new HostCheckFilter("127.0.0.1", "").doFilter(new MockHttpServletRequest("GET", "/"), response, new MockFilterChain());
        assertEquals(403, response.getStatus());
    }

    @Test
    void starLetsAnyHostThrough() throws Exception {
        var chain = new MockFilterChain();
        var response = new MockHttpServletResponse();
        new HostCheckFilter("127.0.0.1", "*").doFilter(request("attacker.example"), response, chain);
        assertNotNull(chain.getRequest());
        assertEquals(200, response.getStatus());
    }

    private static MockHttpServletRequest request(String host) {
        var request = new MockHttpServletRequest("GET", "/api/runs");
        request.addHeader("Host", host);
        return request;
    }
}
