package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.mock.PayerBehaviour;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Keeps {@code payer-matrix.json} from quietly shrinking or drifting: every dimension the issue (#169)
 * names is present with at least two values, every behaviour variant is exercised by some row, and
 * every row cites its spec and states a well-formed expectation.
 */
class PayerMatrixShapeTest {

    static final List<String> DIMENSIONS = List.of(
            "access-token-format", "token-response", "auth-required", "clock", "redirect", "discovery");

    private final PayerMatrix matrix = PayerMatrix.load();

    @Test
    void everyDimensionHasAtLeastTwoValues() {
        assertEquals(DIMENSIONS, matrix.dimensions());
        Map<String, Set<String>> values = new TreeMap<>();
        for (PayerMatrix.Row row : matrix.rows()) {
            assertTrue(DIMENSIONS.contains(row.dimension()), row.id() + " has undeclared dimension " + row.dimension());
            values.computeIfAbsent(row.dimension(), d -> new TreeSet<>()).add(row.value());
        }
        for (String dimension : DIMENSIONS) {
            Set<String> seen = values.getOrDefault(dimension, Set.of());
            assertTrue(seen.size() >= 2, dimension + " needs at least 2 values, has " + seen);
        }
    }

    @Test
    void everyRowCitesItsSpecAndStatesAWellFormedExpectation() {
        Set<String> ids = new HashSet<>();
        Set<String> severities = Stream.concat(Arrays.stream(Severity.values()).map(Enum::name), Stream.of("ABSENT"))
                .collect(Collectors.toSet());
        for (PayerMatrix.Row row : matrix.rows()) {
            assertTrue(ids.add(row.id()), "duplicate row id " + row.id());
            assertTrue(row.id().startsWith(row.dimension() + "/"), row.id() + " should start with its dimension");
            assertTrue(isSet(row.value()) && isSet(row.spec()) && isSet(row.clause()), row.id() + " needs value, spec and clause");
            Objects.requireNonNull(row.auth(), row.id() + " needs auth");
            PayerMatrix.Expect expect = row.expect();
            assertTrue(List.of("PASS", "PASS_WITH_WARNINGS", "FAIL").contains(expect.verdict()), row.id() + " verdict");
            assertTrue(expect.brokeAt() == null || OnboardingRunner.STEP_ORDER.contains(expect.brokeAt()),
                    row.id() + " brokeAt " + expect.brokeAt());
            assertTrue(expect.brokeAt() == null || "FAIL".equals(expect.verdict()),
                    row.id() + ": only a FAIL row can name a broken step");
            assertTrue(!expect.findings().isEmpty(), row.id() + " must name at least one check");
            expect.findings().forEach((check, severity) ->
                    assertTrue(severities.contains(severity), row.id() + ": " + check + " = " + severity));
            assertTrue(row.knownDefect() == null || row.knownDefect().matches("#\\d+"),
                    row.id() + " knownDefect must be an issue reference like #123");
        }
    }

    @Test
    void everyBehaviourVariantIsExercised() {
        List<PayerMatrix.Behaviour> behaviours = matrix.rows().stream().map(PayerMatrix.Row::behaviour)
                .filter(Objects::nonNull).toList();
        Set<Object> seen = new HashSet<>();
        for (PayerMatrix.Behaviour b : behaviours) {
            // What the payer actually does, so a variant a row gets by default (ENFORCED, OPAQUE) counts too.
            PayerBehaviour effective = b.toPayerBehaviour("http://other.invalid", "/token");
            seen.add(effective.accessToken());
            seen.add(effective.hookAuthentication());
            seen.add(effective.discovery());
            seen.add(effective.expiresIn());
            if (b.redirect() != null) {
                seen.add(b.redirect().endpoint() + "/" + b.redirect().to());
                seen.add(b.redirect().status());
            }
        }
        for (Enum<?> variant : Stream.of(PayerBehaviour.AccessToken.values(), PayerBehaviour.HookAuthentication.values(),
                PayerBehaviour.Discovery.values(), PayerBehaviour.ExpiresIn.values()).flatMap(Arrays::stream).toList()) {
            assertTrue(seen.contains(variant), "no row exercises " + variant);
        }
        for (Object redirect : List.of("discovery/same-host", "discovery/other-host", "token/same-host",
                "token/other-host", 307, 308)) {
            assertTrue(seen.contains(redirect), "no row exercises redirect " + redirect);
        }
        assertTrue(behaviours.stream().anyMatch(b -> Boolean.TRUE.equals(b.extraTokenFields()))
                && behaviours.stream().anyMatch(b -> Boolean.TRUE.equals(b.tokenErrorWith200()))
                && behaviours.stream().anyMatch(b -> b.tokenContentType() != null)
                && behaviours.stream().map(PayerMatrix.Behaviour::tokenType).filter(Objects::nonNull).distinct().count() >= 2,
                "every token-response variant needs a row");
        Set<Long> offsets = behaviours.stream().map(PayerMatrix.Behaviour::clockOffsetSeconds).filter(Objects::nonNull)
                .collect(Collectors.toSet());
        assertEquals(Set.of(300L, -300L, 3600L, -3600L), offsets, "clock rows cover +/-5 min and +/-1 h");
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }
}
