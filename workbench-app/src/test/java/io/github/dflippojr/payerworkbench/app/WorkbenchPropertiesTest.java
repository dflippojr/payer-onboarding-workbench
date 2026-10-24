package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A duration or count setting that is out of bounds stops the application from starting, and the
 * message names the setting (#209). Before, it started healthy and each run failed or kept one run.
 */
class WorkbenchPropertiesTest {

    @EnableConfigurationProperties(WorkbenchProperties.class)
    static class Settings {
    }

    private static ApplicationContextRunner context() {
        return new ApplicationContextRunner().withUserConfiguration(Settings.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "workbench.request-timeout=0s",
            "workbench.request-timeout=-1s",
            "workbench.slow-response-delay=-1s",
            "workbench.latency-warn=-1s",
            "workbench.latency-fail=-1s",
            "workbench.max-runs=0",
            "workbench.max-runs=-5"})
    void anOutOfBoundsSettingStopsTheApplicationNamingIt(String property) {
        String setting = property.substring(0, property.indexOf('='));
        context().withPropertyValues(property).run(ctx -> {
            assertNotNull(ctx.getStartupFailure(), "started with " + property);
            String message = rootMessage(ctx.getStartupFailure());
            assertTrue(message.contains(setting), message);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "workbench.slow-response-delay=0s",
            "workbench.latency-warn=0s",
            "workbench.latency-fail=0s",
            "workbench.request-timeout=1s",
            "workbench.max-runs=1"})
    void aValueInsideTheBoundStarts(String property) {
        context().withPropertyValues(property).run(ctx -> assertNull(ctx.getStartupFailure(), property));
    }

    @Test
    void theDefaultsStartAndBindAsDocumented() {
        context().run(ctx -> {
            assertNull(ctx.getStartupFailure());
            WorkbenchProperties properties = ctx.getBean(WorkbenchProperties.class);
            assertEquals(Duration.ofSeconds(11), properties.slowResponseDelay());
            assertEquals(Duration.ofSeconds(5), properties.latencyWarn());
            assertEquals(Duration.ofSeconds(10), properties.latencyFail());
            assertEquals(Duration.ofSeconds(15), properties.requestTimeout());
            assertEquals(200, properties.maxRuns());
        });
    }

    @Test
    void theCanonicalConstructorRefusesTheSameValues() {
        var timeout = assertThrows(IllegalArgumentException.class,
                () -> new WorkbenchProperties(null, null, null, Duration.ZERO, null));
        assertTrue(timeout.getMessage().contains("workbench.request-timeout"), timeout.getMessage());
        var runs = assertThrows(IllegalArgumentException.class,
                () -> new WorkbenchProperties(null, null, null, null, 0));
        assertTrue(runs.getMessage().contains("workbench.max-runs"), runs.getMessage());
    }

    /**
     * Class-level check: every duration and count setting on {@link WorkbenchProperties} refuses a
     * negative value at startup under a message naming it. A setting added later without a bound
     * fails here, without a new row.
     */
    @Test
    void everyDurationAndCountSettingRefusesANegativeValueAtStartup() {
        List<String> checked = new ArrayList<>();
        for (RecordComponent component : WorkbenchProperties.class.getRecordComponents()) {
            Class<?> type = component.getType();
            String value;
            if (type == Duration.class) {
                value = "-1s";
            } else if (type == Integer.class || type == Long.class) {
                value = "-1";
            } else {
                continue;
            }
            String setting = "workbench." + kebab(component.getName());
            checked.add(setting);
            context().withPropertyValues(setting + "=" + value).run(ctx -> {
                assertNotNull(ctx.getStartupFailure(), "started with " + setting + "=" + value);
                String message = rootMessage(ctx.getStartupFailure());
                assertTrue(message.contains(setting), message);
            });
        }
        assertFalse(checked.isEmpty());
    }

    private static String kebab(String camel) {
        return camel.replaceAll("([a-z0-9])([A-Z])", "$1-$2").toLowerCase(Locale.ROOT);
    }

    private static String rootMessage(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage();
    }
}
