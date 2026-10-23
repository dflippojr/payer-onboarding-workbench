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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Class-level check (#177): no payer JSON is read with a coercing Jackson accessor. {@code asLong()},
 * {@code asInt()}, {@code asDouble()} and {@code asBoolean()} turn a value of the wrong JSON type into a
 * plausible one ({@code "abc"} becomes 0, {@code true} becomes 1, {@code "1.5"} becomes 0), so a payer
 * that sends the wrong type gets a clean report for a reason the diagnostics cannot see. That is how a
 * string {@code expires_in} passed {@code auth.token}. A coercing call is allowed only on a line that
 * also checks the node's type ({@code isNumber()}, {@code canConvertToLong()} and the like); otherwise
 * read the field with a typed reader such as {@link ExpiresIn}.
 */
class PayerJsonCoercionTest {

    /** The production code that reads what a payer sends: the runner and the diagnostics. */
    private static final List<Path> ROOTS = List.of(Path.of("src", "main", "java"),
            Path.of("..", "diagnostics", "src", "main", "java"));

    private static final Pattern COERCING = Pattern.compile("\\.as(Long|Int|Double|Boolean)\\(");
    private static final Pattern TYPE_GUARD = Pattern.compile(
            "\\.(isNumber|isIntegralNumber|isInt|isLong|isFloatingPointNumber|isBoolean|canConvertToLong|canConvertToInt)\\(\\)");

    /** Files that read only the workbench's own JSON, with the reason. */
    private static final Map<String, String> OWN_JSON = Map.of(
            "AuditJournal.java", "reads the audit manifest the workbench itself wrote");

    @Test
    void payerJsonIsNeverReadWithACoercingAccessor() throws IOException {
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
                if (OWN_JSON.containsKey(file.getFileName().toString())) {
                    continue;
                }
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (COERCING.matcher(line).find() && !TYPE_GUARD.matcher(line).find()) {
                        offenders.add(file + ":" + (i + 1) + ": " + line.strip());
                    }
                }
            }
        }
        assertTrue(scanned > 20, "scanned only " + scanned + " files; are the roots right?");
        assertEquals(List.of(), offenders, "payer JSON read with a coercing accessor and no type check on the "
                + "same line; check the node's type first or use a typed reader such as ExpiresIn");
    }

    @Test
    void theRuleCatchesTheReadThatLet177Through() {
        String before = "json.hasNonNull(\"expires_in\") ? json.get(\"expires_in\").asLong() : null,";
        String guarded = "return json.path(field).isNumber() ? Instant.ofEpochSecond(json.get(field).asLong()) : null;";
        assertTrue(COERCING.matcher(before).find() && !TYPE_GUARD.matcher(before).find());
        assertTrue(COERCING.matcher(guarded).find() && TYPE_GUARD.matcher(guarded).find());
    }
}
