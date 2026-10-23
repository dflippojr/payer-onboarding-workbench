package io.github.dflippojr.payerworkbench.app;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The raw-line checks in {@link MarkdownTree} agree with cmark-gfm, GitHub's renderer (#213 review). Each input was
 * rendered with cmark-gfm (Python {@code cmarkgfm} 2024.11.20, {@code github_flavored_markdown_to_html}): the ones a
 * check must find made a table or a link there, and the ones it must pass over did not.
 */
class MarkdownTreeTest {

    /** cmark-gfm's table scanner counts VT and FF as spaces, so each of these under a line makes a table. */
    @ParameterizedTest
    @ValueSource(strings = {"Verdict PASS\n\u000b:-:", "Verdict PASS\n\u000c:-:", "Verdict PASS\n \u000b:-:",
            "Verdict PASS\n:-:\u000b"})
    void delimiterRowsCountVerticalTabAndFormFeedAsSpace(String markdown) {
        assertEquals(1, MarkdownTree.delimiterRows(markdown).size(), markdown);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://a.example", "1https://a.example", "_http://a.example", "\\https://a.example",
            "FTP://a.example", "x\nhttps://a.example", "(www.a.example", "*www.a.example",
            "token expired  \nwww.a.example"})
    void autolinksFindWhatCmarkGfmLinks(String markdown) {
        assertEquals(1, MarkdownTree.autolinks(markdown).size(), markdown);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https\\://a.example", "www\\.a.example", "xhttps://a.example", "sftp://a.example",
            "seewww.a.example", "http:/\n/a.example"})
    void autolinksPassOverWhatCmarkGfmLeavesAsText(String markdown) {
        assertEquals(0, MarkdownTree.autolinks(markdown).size(), markdown);
    }
}
