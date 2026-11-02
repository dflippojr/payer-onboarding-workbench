package io.github.dflippojr.payerworkbench.app;

import org.springframework.boot.test.context.SpringBootTest;

/** Bound to a host name, the warm-up posts to that name, which a default proxy would otherwise be asked for (#272). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=localhost")
class WarmupHostNameAddressTest extends WarmupSelfRequestChecks {
}
