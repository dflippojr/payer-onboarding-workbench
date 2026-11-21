package io.github.dflippojr.payerworkbench.core;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.SwitchExpressionTree;
import com.sun.source.tree.SwitchTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Types;
import org.junit.jupiter.api.Test;

/**
 * The member-name checks of {@link JsonRedaction} (#398): the check for a name that repeats in one object, in the text
 * reader and the tree reader, and the check for two names that redact to one. Each goes through
 * {@code JsonRedaction.Names}, an index whose cost per name is linear in the name's length and that takes no hash of a
 * name: a hashed index costs a log factor more on names chosen to collide.
 */
class JsonRedactionNamesTest {

    private static final String JSON_REDACTION = JsonRedaction.class.getName();
    private static final String NAMES = JSON_REDACTION + ".Names";

    /**
     * The name index takes no hash, and the name checks go through it. The log factor a hashed index costs on names
     * chosen to collide is small next to the linear work each name gets on this path (decoding, the key-block check,
     * redaction), so no timing can tell it from noise; the absence of hashing is checked in the code instead, as
     * {@code RedactorTest.indexesFooterLabelsWithoutHashing} checks the armor-label index. {@link #namesIndexViolations}
     * reads the code as the compiler does.
     */
    @Test
    void indexesMemberNamesWithoutHashing() throws IOException {
        List<String> found = namesIndexViolations(CompiledSource.read("JsonRedaction"));
        assertTrue(found.isEmpty(), () -> String.join("\n", found));
    }

    /** The classes whose methods {@code JsonRedaction.Names} may call: none of them hashes what it is given. */
    private static final Set<String> NAMES_CALLEES = Set.of("java.lang.Object", "java.lang.String", "java.lang.Integer",
            "java.lang.Math", "java.util.Arrays");
    /** Methods that hash, or look up a hash table, whatever class declares them. */
    private static final Set<String> HASHING_METHODS = Set.of("hashCode", "identityHashCode", "intern", "hash");
    /** Methods that add to a set or map: building an index of names other than {@code Names}. */
    private static final Set<String> INDEXING_METHODS = Set.of("add", "addAll", "put", "putAll", "putIfAbsent",
            "computeIfAbsent", "compute", "merge");
    /**
     * The methods that check names, {@code Owner.method}, and whether each must call {@code Names.add}: the text
     * reader's object, the tree reader's name, the redaction of a node; and the tree reader's value, which makes the
     * index for each map.
     */
    private static final List<String> NAME_CHECKS = List.of("Reader.readContainer", "TreeReader.name",
            "JsonRedaction.redact(Node)");
    private static final List<String> NAME_SITES = List.of("Reader.readContainer", "TreeReader.name",
            "TreeReader.read", "JsonRedaction.redact(Node)");

    /**
     * What breaks the hash-free rule in {@code source}, a version of {@code JsonRedaction.java}: in
     * {@code JsonRedaction.Names}, a call or method reference to a class other than {@code Names} itself and
     * {@link #NAMES_CALLEES}, a call to one of {@link #HASHING_METHODS}, or a switch on a {@code String}, which
     * compiles to a hash code; a method of {@link #NAME_CHECKS} that does not call {@code Names.add}; and in the
     * methods of {@link #NAME_SITES}, any set or map they make (constructed, or returned by a static factory), any
     * {@link #INDEXING_METHODS} call on a set or map, or a switch on a {@code String}. Fixed sets of names that are
     * only looked up, such as {@link Redactor#JWK_PRIVATE_MEMBERS}, are not indexes and are not reported.
     */
    static List<String> namesIndexViolations(String source) {
        CompiledSource compiled = CompiledSource.compile("JsonRedaction", source);
        Trees trees = compiled.trees();
        Types types = compiled.types();
        TypeElement names = compiled.elements().getTypeElement(NAMES);
        List<String> violations = new ArrayList<>();
        if (names == null) {
            violations.add("JsonRedaction has no class Names");
        } else {
            TreePath path = trees.getPath(names);
            new Rules(trees, types, "Names", violations, true).scan(path, null);
        }
        TypeElement redaction = compiled.type(JSON_REDACTION);
        for (String site : NAME_SITES) {
            ExecutableElement method = method(compiled, redaction, site);
            if (method == null) {
                violations.add("JsonRedaction has no method " + site);
                continue;
            }
            Rules rules = new Rules(trees, types, site, violations, false);
            TreePath path = trees.getPath(method);
            rules.scan(new TreePath(path, ((MethodTree) path.getLeaf()).getBody()), null);
            if (NAME_CHECKS.contains(site) && !rules.called.contains(NAMES + ".add")) {
                violations.add(site + " does not call JsonRedaction.Names.add");
            }
        }
        return violations;
    }

    /** The method {@code site} ({@code Owner.method}, or {@code JsonRedaction.redact(Node)}) of {@code redaction}. */
    private static ExecutableElement method(CompiledSource compiled, TypeElement redaction, String site) {
        String owner = site.substring(0, site.indexOf('.'));
        String rest = site.substring(site.indexOf('.') + 1);
        boolean node = rest.endsWith("(Node)");
        String name = node ? rest.substring(0, rest.indexOf('(')) : rest;
        TypeElement type = owner.equals("JsonRedaction") ? redaction
                : compiled.elements().getTypeElement(JSON_REDACTION + "." + owner);
        if (type == null) {
            return null;
        }
        return type.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.METHOD && e.getSimpleName().contentEquals(name))
                .map(ExecutableElement.class::cast)
                .filter(m -> !node || (!m.getParameters().isEmpty()
                        && m.getParameters().get(0).asType().toString().endsWith(".Node")))
                .findFirst().orElse(null);
    }

    /** Reads one class or method body for the rules of {@link #namesIndexViolations}. */
    private static final class Rules extends TreePathScanner<Void, Void> {
        private final Trees trees;
        private final Types types;
        private final String where;
        private final List<String> violations;
        /** Whether this is {@code Names} itself, which may call only itself and {@link #NAMES_CALLEES}. */
        private final boolean index;
        final Set<String> called = new LinkedHashSet<>();

        Rules(Trees trees, Types types, String where, List<String> violations, boolean index) {
            this.trees = trees;
            this.types = types;
            this.where = where;
            this.violations = violations;
            this.index = index;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            reach(trees.getElement(getCurrentPath()), node);
            if (!index && trees.getElement(getCurrentPath()) instanceof ExecutableElement method
                    && method.getModifiers().contains(javax.lang.model.element.Modifier.STATIC)) {
                // A factory such as Set.of or Collectors.toSet; a set an instance hands out, such as a map's
                // entries, is read, not made.
                TypeMirror returned = trees.getTypeMirror(getCurrentPath());
                if (isCollection(returned, "java.util.Set") || isCollection(returned, "java.util.Map")
                        || isCollection(returned, "java.util.stream.Collector")) {
                    violations.add("in " + where + ": makes a " + returned + " with " + node.getMethodSelect());
                }
            }
            if (!index) {
                if (node.getMethodSelect() instanceof MemberSelectTree select
                        && INDEXING_METHODS.contains(select.getIdentifier().toString())) {
                    TypeMirror receiver = trees.getTypeMirror(new TreePath(getCurrentPath(), select.getExpression()));
                    if (isCollection(receiver, "java.util.Set") || isCollection(receiver, "java.util.Map")) {
                        violations.add("in " + where + ": indexes with " + receiver + "." + select.getIdentifier());
                    }
                }
            }
            return super.visitMethodInvocation(node, unused);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void unused) {
            Element target = trees.getElement(getCurrentPath());
            reach(target, node);
            if (!index && target != null) {
                TypeMirror made = target.getEnclosingElement().asType();
                if (isCollection(made, "java.util.Set") || isCollection(made, "java.util.Map")) {
                    violations.add("in " + where + ": constructs " + types.erasure(made));
                }
            }
            return super.visitNewClass(node, unused);
        }

        @Override
        public Void visitMemberReference(MemberReferenceTree node, Void unused) {
            reach(trees.getElement(getCurrentPath()), node);
            return super.visitMemberReference(node, unused);
        }

        @Override
        public Void visitSwitch(SwitchTree node, Void unused) {
            selector(node.getExpression());
            return super.visitSwitch(node, unused);
        }

        @Override
        public Void visitSwitchExpression(SwitchExpressionTree node, Void unused) {
            selector(node.getExpression());
            return super.visitSwitchExpression(node, unused);
        }

        private void selector(ExpressionTree expression) {
            TypeMirror type = trees.getTypeMirror(new TreePath(getCurrentPath(), expression));
            if (type != null && type.toString().equals("java.lang.String")) {
                violations.add("in " + where + ": switches on a String, which hashes it");
            }
        }

        private void reach(Element target, Tree node) {
            if (!(target instanceof ExecutableElement method)) {
                violations.add("in " + where + ": cannot resolve " + node);
                return;
            }
            String owner = ((TypeElement) method.getEnclosingElement()).getQualifiedName().toString();
            String name = method.getSimpleName().toString();
            called.add(owner + "." + name);
            if (HASHING_METHODS.contains(name)) {
                violations.add("in " + where + ": hashes with " + owner + "." + name);
            } else if (index && !owner.equals(NAMES) && !NAMES_CALLEES.contains(owner)) {
                violations.add("in " + where + ": calls " + owner + "." + name);
            }
        }

        /** Whether {@code type} is, erased, {@code collection} or a subtype of it. */
        private boolean isCollection(TypeMirror type, String collection) {
            if (type == null || type.getKind() != TypeKind.DECLARED) {
                return false;
            }
            TypeMirror erased = types.erasure(type);
            if (types.asElement(erased) instanceof TypeElement element
                    && element.getQualifiedName().contentEquals(collection)) {
                return true;
            }
            return types.directSupertypes(erased).stream().anyMatch(s -> isCollection(s, collection));
        }
    }
}
