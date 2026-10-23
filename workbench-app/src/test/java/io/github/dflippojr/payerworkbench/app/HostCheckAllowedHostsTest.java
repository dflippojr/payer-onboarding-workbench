package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static io.github.dflippojr.payerworkbench.app.HostCheckTest.send;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** {@code workbench.allowed-hosts} adds names to the loopback ones; anything else is still refused (#201). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "workbench.allowed-hosts=workbench.test")
class HostCheckAllowedHostsTest {

    @Value("${local.server.port}")
    int port;

    @Test
    void configuredNameIsAcceptedNextToTheLoopbackOnes() throws Exception {
        assertEquals(200, send(port, "GET", "/api/runs", "workbench.test:" + port, null).status());
        assertEquals(200, send(port, "GET", "/api/runs", "WorkBench.Test", null).status());
        assertEquals(200, send(port, "GET", "/actuator/health", "workbench.test:" + port, null).status());
        assertEquals(200, send(port, "GET", "/api/runs", "127.0.0.1:" + port, null).status());
        assertEquals(403, send(port, "GET", "/api/runs", "attacker.example:" + port, null).status());
        assertEquals(403, send(port, "GET", "/api/runs", "workbench.test.attacker.example", null).status());
    }
}
