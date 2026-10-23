package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.InetAddress;

import static io.github.dflippojr.payerworkbench.app.HostCheckTest.send;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A specific {@code server.address} is allowed in {@code Host} with no {@code workbench.allowed-hosts} (#201).
 * 127.0.0.2 is a loopback address Linux and Windows bind without setup; macOS needs an alias.
 */
@EnabledOnOs({OS.LINUX, OS.WINDOWS})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.2")
class HostCheckBindAddressTest {

    @Value("${local.server.port}")
    int port;

    @Test
    void theBindLiteralIsAllowed() throws Exception {
        InetAddress bound = InetAddress.getByName("127.0.0.2");
        assertEquals(200, send(bound, port, "GET", "/api/runs", "127.0.0.2:" + port, null).status());
        assertEquals(200, send(bound, port, "GET", "/actuator/health", "127.0.0.2", null).status());
        assertEquals(403, send(bound, port, "GET", "/api/runs", "attacker.example:" + port, null).status());
    }
}
