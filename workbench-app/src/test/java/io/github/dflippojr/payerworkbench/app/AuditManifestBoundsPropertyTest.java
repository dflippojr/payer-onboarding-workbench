package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

/**
 * Class-level check (#225): a sealed segment's firstAt and lastAt are the earliest and latest
 * occurredAt values compared as instants, whatever their fractional digits and whatever order they
 * were appended in. Comparing the ISO strings puts a whole second after its own fractions, because
 * {@code .} sorts before {@code Z}, and it also mis-orders 3-, 6- and 9-digit fractions.
 */
class AuditManifestBoundsPropertyTest {

    private static final Instant BASE = Instant.parse("2026-10-08T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(BASE, ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private static final AuditJournal.Policy POLICY =
            new AuditJournal.Policy(Duration.ofDays(30), 10L * 1024 * 1024, 100L * 1024 * 1024);

    private static Path root;

    @BeforeContainer
    static void createRoot() throws IOException {
        root = Files.createTempDirectory("audit-manifest-bounds");
    }

    @AfterContainer
    static void deleteRoot() throws IOException {
        try (Stream<Path> walk = Files.walk(root)) {
            for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(p);
            }
        }
    }

    @Property(tries = 100)
    void sealedBoundsAreTheInstantExtremesForAnyFractionDigitsAndAppendOrder(
            @ForAll("occurrences") List<Instant> occurrences) throws IOException {
        Path dir = Files.createTempDirectory(root, "journal");
        AuditJournal journal = AuditJournal.open(dir.toString(), POLICY, "bench-1", CLOCK, MAPPER);
        for (Instant at : occurrences) {
            journal.append(event(at));
        }
        journal.close();
        // The next opener seals the segment the closed journal left behind.
        AuditJournal.open(dir.toString(), POLICY, "bench-1", CLOCK, MAPPER).close();

        JsonNode segment = MAPPER.readTree(Files.readAllBytes(dir.resolve(AuditJournal.MANIFEST)))
                .path("segments").get(0);
        assertEquals(occurrences.size(), segment.path("events").asInt());
        assertEquals(Collections.min(occurrences), Instant.parse(segment.path("firstAt").asText()));
        assertEquals(Collections.max(occurrences), Instant.parse(segment.path("lastAt").asText()));
    }

    @Provide
    Arbitrary<List<Instant>> occurrences() {
        Arbitrary<Long> nanos = Arbitraries.oneOf(
                Arbitraries.just(0L),
                Arbitraries.of(1L, 1_000L, 1_000_000L, 500_000_000L, 999_999_999L),
                Arbitraries.longs().between(0L, 999_999_999L));
        Arbitrary<Instant> at = Combinators.combine(Arbitraries.longs().between(0L, 2L), nanos)
                .as((seconds, fraction) -> BASE.plusSeconds(seconds).plusNanos(fraction));
        return at.list().ofMinSize(1).ofMaxSize(8);
    }

    private static AuditEvent event(Instant at) {
        return new AuditEvent(1, UUID.randomUUID(), at, "anonymous", null, "http", "run.requested", "started",
                UUID.randomUUID(), null, "run", "target", null);
    }
}
