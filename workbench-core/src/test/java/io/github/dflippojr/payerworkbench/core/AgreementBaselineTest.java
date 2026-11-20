package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;

/**
 * Where the scanner agreement's main baseline comes from (#377 criterion 2, as amended: no new flags against main, row by
 * row). The committed {@code scanner-grids/agreement-main-grid.json.gz} holds main's Redactor output for every input of
 * the agreement grid. This test checks out the baseline revision's own sources by its full commit id, fetching that one
 * commit when the clone does not have it (CI's checkout is shallow), compiles its {@code Redactor} with the JDK's
 * compiler, loads it in a class loader of its own (parent: the platform loader, so none of this module's classes are
 * visible to it), runs every agreement-grid input through it and requires the committed file to hold exactly those
 * outputs, row for row. replay/test/leaks.test.mjs then applies the current scanner to those outputs and requires the
 * committed main verdicts to match; the head pin is a separate file that neither step writes.
 *
 * <p>Regenerate, then review the diff:
 * <pre>
 * ./mvnw -pl workbench-core test -Dtest=AgreementBaselineTest -Dredactor.grids.update=true
 * node scripts/agreement-baseline.mjs          # main's verdicts, from the outputs above, with the current scanner
 * git diff --stat
 * </pre>
 */
class AgreementBaselineTest {

    /** The baseline revision: {@code main} when #377 stage 1 started, before the structural path. */
    static final String BASELINE = "19b624cd5ced541d2f0461b548d4653ff7bcaeeb";

    @Test
    void holdsTheBaselineRevisionsOwnOutputsForEveryAgreementInput() throws Exception {
        Path repo = Path.of(git(Path.of("").toAbsolutePath(), "rev-parse", "--show-toplevel").strip());
        if (run(repo, "git", "cat-file", "-e", BASELINE + "^{commit}") != 0) {
            assertEquals(0, run(repo, "git", "fetch", "--no-tags", "--depth=1", "origin", BASELINE),
                    "fetching the baseline commit " + BASELINE);
        }
        assertEquals(BASELINE, git(repo, "rev-parse", "--verify", BASELINE + "^{commit}").strip());

        Path work = Path.of("target", "agreement-baseline").toAbsolutePath();
        deleteTree(work);
        Path sources = work.resolve("src");
        Path classes = Files.createDirectories(work.resolve("classes"));
        Path zip = work.resolve("sources.zip");
        assertEquals(0, run(repo, "git", "archive", "--format=zip", "--output=" + zip, BASELINE,
                "workbench-core/src/main/java"), "archiving the baseline sources");
        unzip(zip, sources);
        Path root = sources.resolve("workbench-core/src/main/java");
        Path redactor = root.resolve("io/github/dflippojr/payerworkbench/core/Redactor.java");
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-nowarn", "-proc:none",
                "-d", classes.toString(), "-sourcepath", root.toString(), redactor.toString()),
                "compiling the baseline Redactor");

        List<String[]> pairs = new ArrayList<>();
        try (URLClassLoader loader = new URLClassLoader(new URL[] {classes.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> baseline = loader.loadClass(Redactor.class.getName());
            assertNotSame(Redactor.class, baseline);
            assertEquals(loader, baseline.getClassLoader());
            Method redact = baseline.getMethod("redact", String.class);
            for (List<String> pair : RedactorTest.committedScannerGrid("agreement-grid")) {
                pairs.add(new String[] {pair.get(0), (String) redact.invoke(null, pair.get(0))});
            }
        }
        RedactorTest.assertScannerGrid("agreement-main-grid", pairs);
    }

    private static String git(Path dir, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of("git", "-C", dir.toString()));
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), () -> String.join(" ", command));
        return out;
    }

    private static int run(Path dir, String... command) throws IOException, InterruptedException {
        return new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start().waitFor();
    }

    private static void unzip(Path zip, Path into) throws IOException {
        try (InputStream file = Files.newInputStream(zip); ZipInputStream in = new ZipInputStream(file)) {
            for (ZipEntry entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                Path target = into.resolve(entry.getName()).normalize();
                if (!target.startsWith(into)) {
                    throw new IOException("archive entry outside the target: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    Files.copy(in, target);
                }
            }
        }
    }

    private static void deleteTree(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }
}
