package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Renders a {@link RunReport} as Markdown, self-contained HTML or JSON. */
public final class ReportRenderer {

    /** An export format, by its {@code format} query value. */
    public enum Format {
        MD("md", "text/markdown;charset=UTF-8"),
        HTML("html", "text/html;charset=UTF-8"),
        JSON("json", "application/json");

        private final String id;
        private final String mediaType;

        Format(String id, String mediaType) {
            this.id = id;
            this.mediaType = mediaType;
        }

        public String id() {
            return id;
        }

        /** Also the file extension. */
        public String extension() {
            return id;
        }

        public String mediaType() {
            return mediaType;
        }

        public static Optional<Format> fromId(String id) {
            for (Format f : values()) {
                if (f.id.equalsIgnoreCase(id == null ? "" : id.strip())) {
                    return Optional.of(f);
                }
            }
            return Optional.empty();
        }
    }

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Pattern BACKTICKS = Pattern.compile("`+");

    private ReportRenderer() {
    }

    public static String render(RunReport report, Format format) {
        return switch (format) {
            case MD -> markdown(report);
            case HTML -> html(report);
            case JSON -> json(report);
        };
    }

    public static String json(RunReport report) {
        return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report) + "\n";
    }

    // ---- Markdown ----

    public static String markdown(RunReport r) {
        StringBuilder md = new StringBuilder();
        md.append("# ").append(inline(r.title())).append("\n\n");
        md.append("> **").append(inline(r.disclaimer())).append("**\n\n");
        md.append("## Verdict: ").append(r.verdict().status()).append("\n\n");
        md.append(inline(r.verdict().headline())).append("\n\n");
        md.append("| | |\n|---|---|\n");
        row(md, "Payer", r.payer().displayName() + " (`" + r.payer().payerId() + "`)");
        row(md, "Environment", r.environment());
        row(md, "CRD IG version expected", orDash(r.igVersion()));
        row(md, "CRD IG version advertised", orDash(r.advertisedIgVersion()));
        row(md, "Run", "`" + r.runId() + "`");
        row(md, "Run started", orDash(r.startedAt()));
        row(md, "Findings", counts(r.counts()));
        row(md, "Generated", r.generatedAt());
        row(md, "Workbench version", r.workbenchVersion());
        md.append("\n## Step timeline\n\n");
        int n = 1;
        for (RunReport.Step step : r.steps()) {
            md.append(n++).append(". **").append(inline(step.title())).append("**: ").append(step.status());
            if (!step.status().equals("skipped")) {
                md.append(" · ").append(step.elapsedMs()).append(" ms");
            }
            md.append("  \n   ").append(inline(orDash(step.summary()))).append('\n');
            for (String exchange : step.exchanges()) {
                md.append("   - `").append(exchange.replace("`", "'")).append("`\n");
            }
        }
        md.append("\n## Findings\n");
        for (Severity severity : r.counts().keySet()) {
            List<Finding> group = r.findings().stream().filter(f -> f.severity() == severity).toList();
            if (group.isEmpty()) {
                continue;
            }
            md.append("\n### ").append(severity).append(" (").append(group.size()).append(")\n");
            for (Finding f : group) {
                md.append("\n#### ").append(inline(f.title())).append("\n\n");
                md.append("Check: `").append(f.checkId()).append("`\n\n");
                if (f.explanation() != null) {
                    md.append(inline(f.explanation())).append("\n\n");
                }
                if (f.evidence() != null && !f.evidence().isBlank()) {
                    String fence = fenceFor(f.evidence());
                    md.append("Evidence (redacted):\n\n").append(fence).append('\n')
                            .append(f.evidence().strip()).append('\n').append(fence).append("\n\n");
                }
                if (f.suggestedFix() != null) {
                    md.append("**Fix:** ").append(inline(f.suggestedFix())).append("\n\n");
                }
            }
        }
        md.append("\n---\n\n").append(inline(r.disclaimer())).append('\n');
        return md.toString();
    }

    private static void row(StringBuilder md, String label, String value) {
        md.append("| ").append(label).append(" | ").append(value.replace("|", "\\|").replace("\n", " ")).append(" |\n");
    }

    /** One paragraph: line breaks kept as Markdown hard breaks, HTML tags shown literally. */
    private static String inline(String text) {
        return text.strip().replace("<", "&lt;").replace("\r\n", "\n").replace("\n", "  \n");
    }

    /** A code fence longer than any run of backticks inside the evidence. */
    private static String fenceFor(String text) {
        int longest = 0;
        Matcher m = BACKTICKS.matcher(text);
        while (m.find()) {
            longest = Math.max(longest, m.group().length());
        }
        return "`".repeat(Math.max(3, longest + 1));
    }

    // ---- HTML ----

    public static String html(RunReport r) {
        StringBuilder h = new StringBuilder();
        h.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<title>").append(esc(r.title())).append("</title>\n")
                .append("<style>").append(CSS).append("</style>\n</head>\n<body>\n<main>\n");
        h.append("<h1>").append(esc(r.title())).append("</h1>\n");
        h.append("<p class=\"disclaimer\" role=\"note\">").append(esc(r.disclaimer())).append("</p>\n");
        h.append("<section class=\"verdict ").append(esc(r.verdict().status())).append("\">\n<h2>Verdict: ")
                .append(esc(r.verdict().status().replace('_', ' '))).append("</h2>\n<p>")
                .append(esc(r.verdict().headline())).append("</p>\n</section>\n");
        h.append("<table class=\"meta\">\n");
        meta(h, "Payer", esc(r.payer().displayName()) + " <code>" + esc(r.payer().payerId()) + "</code>");
        meta(h, "Environment", esc(r.environment()));
        meta(h, "CRD IG version expected", esc(orDash(r.igVersion())));
        meta(h, "CRD IG version advertised", esc(orDash(r.advertisedIgVersion())));
        meta(h, "Run", "<code>" + esc(r.runId()) + "</code>");
        meta(h, "Run started", esc(orDash(r.startedAt())));
        meta(h, "Findings", esc(counts(r.counts())));
        meta(h, "Generated", esc(r.generatedAt()));
        meta(h, "Workbench version", esc(r.workbenchVersion()));
        h.append("</table>\n");

        h.append("<h2>Step timeline</h2>\n<ol class=\"timeline\">\n");
        for (RunReport.Step step : r.steps()) {
            h.append("<li class=\"step ").append(esc(step.status())).append("\">\n<div class=\"step-head\"><strong>")
                    .append(esc(step.title())).append("</strong> <span class=\"status ").append(esc(step.status()))
                    .append("\">").append(esc(step.status())).append("</span>");
            if (!step.status().equals("skipped")) {
                h.append(" <span class=\"muted\">").append(step.elapsedMs()).append(" ms</span>");
            }
            h.append("</div>\n<p>").append(esc(orDash(step.summary()))).append("</p>\n");
            if (!step.exchanges().isEmpty()) {
                h.append("<ul class=\"exchanges\">");
                for (String exchange : step.exchanges()) {
                    h.append("<li><code>").append(esc(exchange)).append("</code></li>");
                }
                h.append("</ul>\n");
            }
            h.append("</li>\n");
        }
        h.append("</ol>\n");

        h.append("<h2>Findings</h2>\n");
        for (Severity severity : r.counts().keySet()) {
            List<Finding> group = r.findings().stream().filter(f -> f.severity() == severity).toList();
            if (group.isEmpty()) {
                continue;
            }
            h.append("<section class=\"sev-group\">\n<h3><span class=\"sev ").append(severity).append("\">")
                    .append(severity).append("</span> ").append(group.size()).append(" finding")
                    .append(group.size() == 1 ? "" : "s").append("</h3>\n");
            for (Finding f : group) {
                h.append("<article class=\"finding ").append(severity).append("\">\n<h4>").append(esc(f.title()))
                        .append("</h4>\n<p class=\"muted\"><code>").append(esc(f.checkId())).append("</code></p>\n");
                if (f.explanation() != null) {
                    h.append("<p>").append(esc(f.explanation())).append("</p>\n");
                }
                if (f.evidence() != null && !f.evidence().isBlank()) {
                    h.append("<p class=\"label\">Evidence (redacted)</p>\n<pre>").append(esc(f.evidence().strip()))
                            .append("</pre>\n");
                }
                if (f.suggestedFix() != null) {
                    h.append("<p class=\"fix\"><strong>Fix:</strong> ").append(esc(f.suggestedFix())).append("</p>\n");
                }
                h.append("</article>\n");
            }
            h.append("</section>\n");
        }
        h.append("<footer>").append(esc(r.disclaimer())).append("<br>Generated ").append(esc(r.generatedAt()))
                .append(" by payer onboarding workbench ").append(esc(r.workbenchVersion())).append(".</footer>\n");
        h.append("</main>\n</body>\n</html>\n");
        return h.toString();
    }

    private static void meta(StringBuilder h, String label, String valueHtml) {
        h.append("<tr><th scope=\"row\">").append(esc(label)).append("</th><td>").append(valueHtml).append("</td></tr>\n");
    }

    static String esc(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    private static String counts(Map<Severity, Long> counts) {
        StringBuilder out = new StringBuilder();
        counts.forEach((severity, count) -> out.append(out.isEmpty() ? "" : ", ")
                .append(count).append(' ').append(severity.name().toLowerCase(Locale.ROOT)));
        return out.toString();
    }

    private static String orDash(String text) {
        return text == null || text.isBlank() ? "—" : text;
    }

    /** Inline so the file stands alone; the print rules keep findings whole and colours on paper. */
    private static final String CSS = """
            :root{--fg:#1d2430;--muted:#5b6575;--line:#d9dee7;--pass:#1f7a3f;--info:#2759a5;--warn:#9a5b00;--fail:#b3261e}
            *{box-sizing:border-box}
            body{margin:0;color:var(--fg);background:#fff;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
            main{max-width:900px;margin:0 auto;padding:32px 24px}
            h1{font-size:1.6rem;margin:0 0 12px}h2{font-size:1.2rem;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:4px}
            h3{font-size:1.05rem;margin:18px 0 8px}h4{margin:0 0 4px;font-size:1rem}
            code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85em}
            pre{background:#f5f7fa;border:1px solid var(--line);border-radius:6px;padding:10px;white-space:pre-wrap;overflow-wrap:anywhere}
            .muted{color:var(--muted)}.label{font-weight:600;margin:8px 0 4px}
            .disclaimer{border-left:4px solid var(--warn);background:#fff8eb;padding:10px 12px;margin:0 0 16px}
            .verdict{border:1px solid var(--line);border-left-width:6px;border-radius:6px;padding:4px 16px;margin:16px 0}
            .verdict h2{border:0;margin:10px 0 4px}.verdict.PASS{border-left-color:var(--pass)}
            .verdict.PASS_WITH_WARNINGS{border-left-color:var(--warn)}.verdict.FAIL{border-left-color:var(--fail)}
            table.meta{border-collapse:collapse;width:100%}table.meta th,table.meta td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}
            table.meta th{width:34%;font-weight:600;color:var(--muted)}
            .timeline{padding-left:22px}.step{margin:0 0 10px}.step p{margin:2px 0}
            .status{display:inline-block;padding:0 8px;border-radius:10px;font-size:.8em;border:1px solid currentColor}
            .status.passed{color:var(--pass)}.status.failed{color:var(--fail)}.status.skipped{color:var(--muted)}
            .exchanges{margin:4px 0;padding-left:18px;color:var(--muted)}
            .sev{display:inline-block;min-width:52px;text-align:center;padding:0 8px;border-radius:4px;color:#fff;font-size:.85em;margin-right:6px}
            .sev.PASS{background:var(--pass)}.sev.INFO{background:var(--info)}.sev.WARN{background:var(--warn)}.sev.FAIL{background:var(--fail)}
            .finding{border:1px solid var(--line);border-left-width:5px;border-radius:6px;padding:10px 14px;margin:0 0 10px}
            .finding.PASS{border-left-color:var(--pass)}.finding.INFO{border-left-color:var(--info)}
            .finding.WARN{border-left-color:var(--warn)}.finding.FAIL{border-left-color:var(--fail)}
            .finding p{margin:6px 0}.fix{background:#f1f7f2;padding:6px 8px;border-radius:4px}
            footer{margin-top:32px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:.85em}
            @page{margin:16mm}
            @media print{body{font-size:11pt}main{max-width:none;padding:0}
            *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
            .finding,.step,.verdict,pre,tr{break-inside:avoid}h2,h3,h4{break-after:avoid}}
            """;
}
