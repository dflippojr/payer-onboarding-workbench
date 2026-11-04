package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * Class-level check (#299): a {@code baseUrlSuffix} that {@link OnboardingRunner#withSuffix} accepts
 * leaves the request path exactly where it says, under the base URL's path, as a server that removes
 * dot-segments (RFC 3986 section 5.2.4) and decodes {@code %2e} would see it. This catches any suffix
 * that escapes or rewrites the base path with {@code .} or {@code ..} segments, raw or percent-encoded
 * in any case, not only the inputs listed in #299.
 */
class BaseUrlSuffixPropertyTest {

    private static final String BASE = "https://payer.example/fhir/r4";
    private static final List<String> SAFE = List.of("abc", "r4", "a.b", "..c", "...", ".x", "x.", "%2ex", "a%2E", "");
    private static final List<String> DOTS = List.of(".", "..", "%2e", "%2E", "%2e%2E", ".%2e", "%2E.");

    @Property
    void anAcceptedSuffixStaysUnderTheBasePath(@ForAll("suffixes") String suffix) {
        String combined;
        try {
            combined = OnboardingRunner.withSuffix(BASE, suffix);
        } catch (IllegalArgumentException refused) {
            return;
        }
        URI asServerSeesIt = URI.create(combined.replaceAll("(?i)%2e", "."));
        String path = asServerSeesIt.getRawPath().replaceAll("/{2,}", "/");
        assertEquals(path, asServerSeesIt.normalize().getRawPath(), suffix + " has a dot-segment the server would resolve");
        assertTrue(path.startsWith(URI.create(BASE).getRawPath() + "/"), suffix + " left the base path: " + path);
    }

    @Property
    void aSuffixWithoutDotSegmentsIsAccepted(@ForAll("safeSuffixes") String suffix) {
        assertEquals(BASE + suffix, OnboardingRunner.withSuffix(BASE, suffix));
    }

    @Provide
    Arbitrary<String> suffixes() {
        Arbitrary<String> segment = Arbitraries.oneOf(Arbitraries.of(SAFE), Arbitraries.of(DOTS));
        return segment.list().ofMinSize(1).ofMaxSize(6).map(segments -> "/" + String.join("/", segments));
    }

    @Provide
    Arbitrary<String> safeSuffixes() {
        return Arbitraries.of(SAFE).list().ofMinSize(1).ofMaxSize(6).map(segments -> "/" + String.join("/", segments));
    }
}
