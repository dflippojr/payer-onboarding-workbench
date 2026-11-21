package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.source.util.JavacTask;
import com.sun.source.util.Trees;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.lang.model.element.TypeElement;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

/**
 * A version of one source file of this package, compiled by the JDK's compiler against this module's classes, for the
 * hash-free guards that read code as the compiler does ({@code RedactorTest}, {@code JsonRedactionNamesTest}):
 * comments and literals are not part of the trees they read.
 */
record CompiledSource(Trees trees, Elements elements, Types types) {

    /** The source of {@code simpleName}{@code .java} in this package, read from this module. */
    static String read(String simpleName) throws IOException {
        return Files.readString(Path.of("src/main/java/io/github/dflippojr/payerworkbench/core/" + simpleName + ".java"));
    }

    /** {@code source}, a version of {@code simpleName}{@code .java} in this package, compiled; fails if it does not compile. */
    static CompiledSource compile(String simpleName, String source) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "the hash-free guard needs the JDK's compiler");
        JavaFileObject file = new SimpleJavaFileObject(URI.create(
                "string:///io/github/dflippojr/payerworkbench/core/" + simpleName + ".java"), JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return source;
            }
        };
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        String classPath = "target/classes" + File.pathSeparator + System.getProperty("java.class.path");
        JavacTask task = (JavacTask) compiler.getTask(null, null, diagnostics,
                List.of("-proc:none", "-implicit:none", "-classpath", classPath), null, List.of(file));
        try {
            task.parse();
            task.analyze();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        List<String> errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR).map(Object::toString).toList();
        assertTrue(errors.isEmpty(), () -> simpleName + ".java does not compile:\n" + String.join("\n", errors));
        return new CompiledSource(Trees.instance(task), task.getElements(), task.getTypes());
    }

    /** The compiled class {@code qualifiedName}, nested ones spelled with dots. */
    TypeElement type(String qualifiedName) {
        TypeElement type = elements.getTypeElement(qualifiedName);
        assertNotNull(type, () -> "no class " + qualifiedName);
        return type;
    }

    /** {@code source} with its one {@code target} replaced, failing if {@code target} is not there exactly once. */
    static String replaceOnce(String source, String target, String replacement) {
        int at = source.indexOf(target);
        assertTrue(at >= 0 && source.indexOf(target, at + 1) < 0, () -> "not found once in the source:\n" + target);
        return source.substring(0, at) + replacement + source.substring(at + target.length());
    }
}
