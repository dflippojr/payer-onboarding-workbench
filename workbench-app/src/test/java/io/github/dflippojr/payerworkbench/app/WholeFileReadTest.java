package io.github.dflippojr.payerworkbench.app;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Class-level check (#223): production code never loads a whole file or stream into memory without a
 * bound. {@code Files.readAllBytes} on a 2 GiB journal segment threw {@code OutOfMemoryError}, an
 * {@code Error} that the journal's {@code IOException | RuntimeException} handlers could not contain, so
 * startup failed instead of falling back to log-only audit. Stream the file, or read a small one with
 * {@link AuditJournal#readBounded}, which refuses anything over its limit.
 */
class WholeFileReadTest {

    private static final List<Path> ROOTS = List.of(Path.of("src", "main", "java"),
            Path.of("..", "workbench-core", "src", "main", "java"),
            Path.of("..", "diagnostics", "src", "main", "java"),
            Path.of("..", "samples", "src", "main", "java"),
            Path.of("..", "mock-payers", "src", "main", "java"));

    static final Pattern UNBOUNDED = Pattern.compile(
            "Files\\.(readAllBytes|readString|readAllLines|lines)\\(|\\.readAllBytes\\(\\)"
                    + "|\\.read(Tree|Value)\\([^;]*(\\.toFile\\(\\)|new File\\()");

    /** Unbounded reads that are allowed, with the reason. */
    private static final Map<String, String> ALLOWED = Map.of(
            "MockPayer.java", "the synthetic payer reads request bodies the workbench under test sends it");

    @Test
    void productionCodeNeverReadsAWholeFileUnbounded() throws IOException {
        List<String> offenders = new ArrayList<>();
        int scanned = 0;
        for (Path root : ROOTS) {
            assertTrue(Files.isDirectory(root), root.toAbsolutePath() + " is missing");
            List<Path> files;
            try (Stream<Path> walk = Files.walk(root)) {
                files = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
            }
            for (Path file : files) {
                scanned++;
                if (ALLOWED.containsKey(file.getFileName().toString())) {
                    continue;
                }
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    if (UNBOUNDED.matcher(lines.get(i)).find()) {
                        offenders.add(file + ":" + (i + 1) + ": " + lines.get(i).strip());
                    }
                }
            }
        }
        assertTrue(scanned > 20, "scanned only " + scanned + " files; are the roots right?");
        assertEquals(List.of(), offenders, "whole file read into memory with no bound; a big file throws "
                + "OutOfMemoryError, which IOException handlers cannot contain. Stream it or use readBounded");
    }

    @Test
    void theRuleCatchesTheReadThatLet223Through() {
        assertTrue(UNBOUNDED.matcher("byte[] bytes = Files.readAllBytes(dir.resolve(id + \".jsonl\"));").find());
        assertTrue(UNBOUNDED.matcher("JsonNode root = mapper.readTree(Files.readAllBytes(manifest));").find());
        assertTrue(UNBOUNDED.matcher("String body = new String(in.readAllBytes(), UTF_8);").find());
        assertTrue(UNBOUNDED.matcher("JsonNode n = mapper.readTree(path.toFile());").find());
        assertFalse(UNBOUNDED.matcher("byte[] bytes = in.readNBytes(max + 1);").find());
        assertFalse(UNBOUNDED.matcher("JsonNode root = mapper.readTree(readBounded(manifest, MAX));").find());
    }
}
