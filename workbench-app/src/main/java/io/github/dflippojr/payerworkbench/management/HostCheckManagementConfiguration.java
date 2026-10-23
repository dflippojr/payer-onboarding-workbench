package io.github.dflippojr.payerworkbench.management;

import io.github.dflippojr.payerworkbench.app.HostCheckFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextType;
import org.springframework.context.annotation.Bean;

/**
 * The {@link HostCheckFilter} for actuator on a port of its own ({@code management.server.port}): that server
 * runs in a child context, which doesn't get the application's filters. Its bind literal is
 * {@code management.server.address}. It lives outside the application's scanned package: a
 * {@code @ManagementContextConfiguration} is also a {@code @Configuration}, and scanned into the main context
 * it would add a second filter there that doesn't know {@code server.address}.
 */
@ManagementContextConfiguration(value = ManagementContextType.CHILD, proxyBeanMethods = false)
class HostCheckManagementConfiguration {

    @Bean
    HostCheckFilter managementHostCheckFilter(@Value("${management.server.address:}") String managementAddress,
                                              @Value("${" + HostCheckFilter.SETTING + ":}") String allowedHosts) {
        return new HostCheckFilter(managementAddress, allowedHosts);
    }
}
