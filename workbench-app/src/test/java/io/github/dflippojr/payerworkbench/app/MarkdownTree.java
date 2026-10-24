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
 * cmark-gfm, GitHub's renderer, leaves as text; {@link #autolinks} scans the raw lines instead.
 */
final class MarkdownTree {

    private static final Parser PARSER = Parser.builder().extensions(List.of(TablesExtension.create(),
            StrikethroughExtension.create(), TaskListItemsExtension.create(), FootnotesExtension.create())).build();
    /** Spaces as cmark-gfm's table scanner counts them: space, tab, VT and FF. */
    private static final String TABLE_SPACE = "[ \\t\\x0B\\f]*+";
    private static final String DELIMITER_CELL = TABLE_SPACE + ":?+-++:?+" + TABLE_SPACE;
    /**
     * A GFM table delimiter row as cmark-gfm, GitHub's renderer, scans it: cells of {@code :?-+:?} split by pipes,
     * with no pipe needed. commonmark-java's tables extension wants a pipe, so it misses {@code Verdict: PASS} over
     * {@code :-:}, which GitHub renders as a one-column table.
     */
    private static final Pattern DELIMITER_ROW = Pattern.compile(
            TABLE_SPACE + "\\|?+" + DELIMITER_CELL + "(?:\\|" + DELIMITER_CELL + ")*+\\|?+" + TABLE_SPACE);
    /**
     * Where cmark-gfm's extended autolinks start in raw text: {@code http://}, {@code https://} or {@code ftp://} in
     * any case after anything but an ASCII letter (a digit, {@code _} or backslash before it does not stop the link),
     * and {@code www.} after anything but a letter or digit. A little wider than cmark-gfm, which links {@code www.}
     * only in lower case, at a line start or after a space or one of {@code *_~(}. An escaped {@code \://} or
     * {@code \.} breaks the match, as it breaks the link.
     */
    private static final String URL = "(?<![a-z])(?:https?|ftp)://|(?<![a-z0-9])www\\.";
    /**
     * Where cmark-gfm's extended email autolinks, {@code mailto:} and {@code xmpp:} included, have their {@code @}: a
     * local-part character ({@code [A-Za-z0-9.+_-]}, or the {@code :} of {@code mailto:}), the {@code @}, then
     * domain characters up to a {@code .} with a letter or digit after it. cmark-gfm links the text after escapes and
     * character references are resolved, so {@code \@}, {@code \.}, {@code \_}, {@code &#64;} and {@code &#46;} still
     * match; an escaped backslash or an inline node such as a code span next to the {@code @} breaks the match, as it
     * breaks the link. A little wider than cmark-gfm, which also wants the domain to end in a letter and allows the
     * {@code :} only in {@code mailto:} or {@code xmpp:}.
     */
    private static final String EMAIL = "[a-z0-9.+_:-](?:\\\\?@|&#0*+64;|&#x0*+40;|&commat;)(?:[a-z0-9_-]|\\\\[_-])*+"
            + "(?:\\\\?\\.|&#0*+46;|&#x0*+2e;|&period;)[a-z0-9]";
    private static final Pattern AUTOLINK = Pattern.compile("(?i)" + URL + "|" + EMAIL);

    private MarkdownTree() {
    }

    static Node parse(String markdown) {
        return PARSER.parse(markdown);
    }

    /** The lines a GFM renderer could read as a table's delimiter row, in document order. */
    static List<String> delimiterRows(String markdown) {
        return markdown.lines().filter(line -> DELIMITER_ROW.matcher(line).matches()).toList();
    }

    /** The line of each bare URL or email address a GFM renderer could autolink, once per link, in document order. */
    static List<String> autolinks(String markdown) {
        return markdown.lines().flatMap(line -> AUTOLINK.matcher(line).results().map(m -> line)).toList();
    }

    /** Every node, depth first. */
    static List<Node> nodes(Node root) {
        List<Node> out = new ArrayList<>();
        collect(root, out);
        return out;
    }

    /**
     * Node kinds in document order, without text, line breaks and the code span that shows each run of {@code @} in
     * payer text (#213 owner decision); a heading carries its level.
     */
    static List<String> shape(Node root) {
        return nodes(root).stream()
                .filter(n -> !(n instanceof Text || n instanceof HardLineBreak || n instanceof SoftLineBreak
                        || n instanceof Code c && c.getLiteral().matches("@++")))
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
