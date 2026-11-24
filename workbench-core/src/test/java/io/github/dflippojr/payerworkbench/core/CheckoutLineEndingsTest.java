package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Every committed text file is stored with the line endings .gitattributes names for it, so a fresh checkout is clean.
 *
 * <p>The rules {@code * text=auto} and {@code *.cmd text eol=crlf} store text as LF in the index and check it out as CRLF.
 * A blob committed with CRLF never equals its own normalized form, so git reports the file modified right after checkout.
 * That is how main went dirty with #418 (f929922, which re-committed {@code mvnw.cmd} with CRLF); 0b3cd97 and 6b6b699 had
 * already done the same. This test reads the index only ({@code git ls-files --eol}), so it never writes the index or the
 * working tree and ignores a developer's uncommitted edits. Fix a failure with {@code git add --renormalize -- <path>}
 * and commit it.
 */
class CheckoutLineEndingsTest {

    @Test
    void everyCommittedTextFileIsStoredWithLfLineEndings() throws Exception {
        Path repo = Path.of(git(Path.of("").toAbsolutePath(), "rev-parse", "--show-toplevel").strip());
        int textFiles = 0;
        List<String> crlf = new ArrayList<>();
        for (String line : git(repo, "ls-files", "--eol").split("\n")) {
            // A row is "i/<index eol> w/<working-tree eol> attr/<attributes>", a tab, then the path. The working-tree
            // field is empty for a tracked file that is missing from the working tree, so split the row, don't match it.
            String[] columns = line.split("\t", 2);
            int attr = columns.length == 2 ? columns[0].indexOf("attr/") : -1;
            assertTrue(columns.length == 2 && columns[0].startsWith("i/") && attr > 0,
                    () -> "unexpected git ls-files --eol row: " + line);
            String indexEol = columns[0].substring(2).split("\\s+", 2)[0];
            List<String> attributes = Arrays.asList(columns[0].substring(attr + "attr/".length()).strip().split("\\s+"));
            boolean text = !attributes.contains("-text") && !attributes.contains("binary")
                    && attributes.stream().anyMatch(a -> a.equals("text") || a.startsWith("text="));
            if (!text) {
                continue;
            }
            textFiles++;
            if (indexEol.equals("crlf") || indexEol.equals("mixed")) {
                crlf.add(columns[1] + " (i/" + indexEol + ")");
            }
        }
        assertTrue(textFiles > 0, "no text files found: run this test in a git checkout");
        assertEquals(List.of(), crlf, () -> "committed with CRLF line endings, but .gitattributes stores text as LF, "
                + "so a fresh checkout reports these modified: " + String.join(", ", crlf)
                + ". Fix each with: git add --renormalize -- <path>, then commit.");
    }

    private static String git(Path dir, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of("git", "-C", dir.toString()));
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), () -> String.join(" ", command));
        return out;
    }
}
