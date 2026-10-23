package io.github.dflippojr.payerworkbench.app;

import org.commonmark.ext.footnotes.FootnotesExtension;
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension;
import org.commonmark.ext.gfm.tables.TableCell;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.ext.task.list.items.TaskListItemsExtension;
import org.commonmark.node.Block;
import org.commonmark.node.Code;
import org.commonmark.node.FencedCodeBlock;
import org.commonmark.node.HardLineBreak;
import org.commonmark.node.Heading;
import org.commonmark.node.Node;
import org.commonmark.node.SoftLineBreak;
import org.commonmark.node.Text;
import org.commonmark.parser.Parser;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The Markdown report as a CommonMark parser with GFM tables, strikethrough, task lists and footnotes sees it (#213).
 * Not the autolink extension: it links URLs in text after escapes are resolved, so it links {@code https\://x}, which
 * cmark-gfm, GitHub's renderer, leaves as text.
 */
final class MarkdownTree {

    private static final Parser PARSER = Parser.builder().extensions(List.of(TablesExtension.create(),
            StrikethroughExtension.create(), TaskListItemsExtension.create(), FootnotesExtension.create())).build();
    /**
     * A GFM table delimiter row as cmark-gfm, GitHub's renderer, scans it: cells of {@code :?-+:?} split by pipes,
     * with no pipe needed. commonmark-java's tables extension wants a pipe, so it misses {@code Verdict: PASS} over
     * {@code :-:}, which GitHub renders as a one-column table.
     */
    private static final Pattern DELIMITER_ROW =
            Pattern.compile("[ \\t]*+\\|?+[ \\t]*+:?+-++:?+[ \\t]*+(?:\\|[ \\t]*+:?+-++:?+[ \\t]*+)*+\\|?+[ \\t]*+");

    private MarkdownTree() {
    }

    static Node parse(String markdown) {
        return PARSER.parse(markdown);
    }

    /** The lines a GFM renderer could read as a table's delimiter row, in document order. */
    static List<String> delimiterRows(String markdown) {
        return markdown.lines().filter(line -> DELIMITER_ROW.matcher(line).matches()).toList();
    }

    /** Every node, depth first. */
    static List<Node> nodes(Node root) {
        List<Node> out = new ArrayList<>();
        collect(root, out);
        return out;
    }

    /** Node kinds in document order, without text and line breaks; a heading carries its level. */
    static List<String> shape(Node root) {
        return nodes(root).stream()
                .filter(n -> !(n instanceof Text || n instanceof HardLineBreak || n instanceof SoftLineBreak))
                .map(n -> n instanceof Heading h ? "Heading" + h.getLevel() : n.getClass().getSimpleName())
                .toList();
    }

    /** What a reader sees: the literal text, a line break as a newline and each block on a line of its own. */
    static String text(Node root) {
        StringBuilder out = new StringBuilder();
        text(root, out);
        return out.toString();
    }

    private static void collect(Node node, List<Node> out) {
        out.add(node);
        for (Node child = node.getFirstChild(); child != null; child = child.getNext()) {
            collect(child, out);
        }
    }

    private static void text(Node node, StringBuilder out) {
        switch (node) {
            case Text t -> out.append(t.getLiteral());
            case Code c -> out.append(c.getLiteral());
            case FencedCodeBlock f -> out.append(f.getLiteral());
            case HardLineBreak b -> out.append('\n');
            case SoftLineBreak b -> out.append('\n');
            default -> {
            }
        }
        for (Node child = node.getFirstChild(); child != null; child = child.getNext()) {
            text(child, out);
        }
        if (node instanceof Block || node instanceof TableCell) {
            out.append('\n');
        }
    }
}
