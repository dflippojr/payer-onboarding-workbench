package io.github.dflippojr.payerworkbench.app;

import org.commonmark.ext.gfm.tables.TableCell;
import org.commonmark.ext.gfm.tables.TablesExtension;
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

/** The Markdown report as a CommonMark parser with GFM tables sees it (#213). */
final class MarkdownTree {

    private static final Parser PARSER = Parser.builder().extensions(List.of(TablesExtension.create())).build();

    private MarkdownTree() {
    }

    static Node parse(String markdown) {
        return PARSER.parse(markdown);
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
