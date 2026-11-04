package io.github.dflippojr.payerworkbench.app;

import org.springframework.boot.test.context.SpringBootTest;

/** Bound to every interface, the warm-up uses 127.0.0.1, which {@link HostCheckFilter} always allows (#272). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=0.0.0.0")
class WarmupWildcardAddressTest extends WarmupSelfRequestChecks {
}
