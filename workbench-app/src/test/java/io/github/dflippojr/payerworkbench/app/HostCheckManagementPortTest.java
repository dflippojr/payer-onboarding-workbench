package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalManagementPort;

import static io.github.dflippojr.payerworkbench.app.HostCheckTest.send;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** Actuator on a port of its own, as the README's Observability section describes, keeps the Host check (#201). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"management.server.port=0", "management.server.address=127.0.0.1"})
class HostCheckManagementPortTest {

    @LocalManagementPort
    int managementPort;

    @Test
    void foreignHostIsRefusedOnTheManagementPort() throws Exception {
        String host = "attacker.example:" + managementPort;
        assertEquals(403, send(managementPort, "GET", "/actuator/health", host, null).status());
        assertEquals(403, send(managementPort, "GET", "/actuator/prometheus", host, null).status());
        assertEquals(200, send(managementPort, "GET", "/actuator/health", "127.0.0.1:" + managementPort, null).status());
        assertEquals(200, send(managementPort, "GET", "/actuator/prometheus", "localhost:" + managementPort, null).status());
    }
}
