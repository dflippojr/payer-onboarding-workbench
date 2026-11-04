package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Bound to a specific address, nothing listens on 127.0.0.1, so the warm-up has to use that address (#272).
 * 127.0.0.2 stands in for a LAN address: Linux and Windows bind it without setup; macOS needs an alias.
 */
@EnabledOnOs({OS.LINUX, OS.WINDOWS})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.2")
class WarmupBoundAddressTest extends WarmupSelfRequestChecks {
}
