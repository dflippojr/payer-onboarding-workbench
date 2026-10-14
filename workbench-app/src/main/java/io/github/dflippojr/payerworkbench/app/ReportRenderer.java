package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.Severity;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
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
        row(md, "Correlation id (" + RequestIdClient.HEADER + ")", "`" + r.correlationId() + "`");
        row(md, "Run started", orDash(r.startedAt()));
        row(md, "Findings", counts(r.counts()));
        row(md, "Generated", r.generatedAt());
        row(md, "Workbench version", r.workbenchVersion());
        FailingCall.of(r).ifPresent(call -> mdFailingCall(md, call));
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

    private static void mdFailingCall(StringBuilder md, FailingCall call) {
        md.append("\n## Failing call\n\n");
        md.append("The last call of the **").append(inline(call.stepTitle())).append("** step. ")
                .append(FAILING_CALL_NOTE).append("\n\n");
        md.append("`").append(call.method().replace("`", "'")).append(' ').append(call.url().replace("`", "'"))
                .append("` → ").append(callOutcome(call)).append("\n\n");
        mdBlock(md, "Request headers", String.join("\n", call.requestHeaders()), "");
        mdBody(md, "Request body", call.requestBody());
        if (call.transportError() != null) {
            mdBlock(md, "Transport error", call.transportError(), "");
        }
        mdBlock(md, "Response headers", String.join("\n", call.responseHeaders()), "");
        mdBody(md, "Response body", call.responseBody());
        md.append("**Reproduce with curl**\n\n").append(inline(curlNote(call))).append("\n\n");
        String fence = fenceFor(call.curl());
        md.append(fence).append("sh\n").append(call.curl()).append('\n').append(fence).append('\n');
    }

    private static void mdBody(StringBuilder md, String label, FailingCall.Body body) {
        if (body == null) {
            md.append("**").append(label).append(":** none\n\n");
            return;
        }
        mdBlock(md, label, body.text().stripTrailing(), body.json() ? "json" : "");
        if (body.truncated()) {
            md.append("*").append(FailingCall.TRUNCATED_NOTE).append("*\n\n");
        }
    }

    private static void mdBlock(StringBuilder md, String label, String text, String language) {
        if (text.isBlank()) {
            md.append("**").append(label).append(":** none\n\n");
            return;
        }
        String fence = fenceFor(text);
        md.append("**").append(label).append("**\n\n").append(fence).append(language).append('\n')
                .append(text).append('\n').append(fence).append("\n\n");
    }

    private static final String FAILING_CALL_NOTE = "Credentials, tokens, cookies and secrets are redacted.";

    private static String callOutcome(FailingCall call) {
        return call.status() + (call.latencyMs() == null ? "" : " · " + call.latencyMs() + " ms");
    }

    private static String curlNote(FailingCall call) {
        return (call.bodyFile() == null ? "" : "Save the request body above as " + call.bodyFile() + ". ")
                + "Replace each placeholder in angle brackets with your own credential.";
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

    private static final DateTimeFormatter UTC_SECONDS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT).withZone(ZoneOffset.UTC);

    /** Inline status icons; each sits beside a word, so colour is never the only signal. */
    private static final String ICON_PASS = "<circle cx=\"10\" cy=\"10\" r=\"8.5\"/><path d=\"M6.5 10.2l2.3 2.3 4.7-4.9\"/>";
    private static final String ICON_FAIL = "<circle cx=\"10\" cy=\"10\" r=\"8.5\"/><path d=\"M7 7l6 6M13 7l-6 6\"/>";
    private static final String ICON_WARN = "<path d=\"M10 2.5l8 14.5H2z\"/><path d=\"M10 8v4M10 14.5v.5\"/>";
    private static final String ICON_INFO = "<circle cx=\"10\" cy=\"10\" r=\"8.5\"/><path d=\"M10 9v5M10 6v.5\"/>";
    private static final String ICON_SKIP = "<circle cx=\"10\" cy=\"10\" r=\"8.5\" stroke-dasharray=\"3 3\"/><path d=\"M6.5 10h7\"/>";
    private static final String ICON_FIX = "<path d=\"M4 10.5l4 4 8-9\"/>";

    public static String html(RunReport r) {
        StringBuilder h = new StringBuilder();
        String payerName = r.payer().displayName() == null ? r.payer().payerId() : r.payer().displayName();
        h.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<title>").append(esc(r.title())).append("</title>\n")
                .append("<style>").append(CSS).append("</style>\n</head>\n<body>\n<main>\n");
        h.append("<header>\n<p class=\"kicker\">Payer onboarding report</p>\n<h1>").append(esc(payerName))
                .append("</h1>\n<p class=\"sub\">").append(esc(r.environment())).append(" · run ").append(esc(r.runId()))
                .append(" · generated ").append(utc(r.generatedAt())).append("</p>\n</header>\n");
        h.append("<p class=\"disclaimer\" role=\"note\">").append(icon(ICON_WARN, 18, "")).append("<span>")
                .append(esc(r.disclaimer())).append("</span></p>\n");
        htmlVerdict(h, r);

        h.append("<dl class=\"facts\">\n");
        fact(h, "Payer", esc(r.payer().displayName()) + " <code>" + esc(r.payer().payerId()) + "</code>");
        fact(h, "Environment", esc(r.environment()));
        fact(h, "CRD IG version", esc(orDash(r.igVersion())) + " expected · " + esc(orDash(r.advertisedIgVersion()))
                + " advertised");
        fact(h, "Run started", utc(r.startedAt()));
        fact(h, "Run", "<code>" + esc(r.runId()) + "</code>");
        fact(h, "Correlation id (" + RequestIdClient.HEADER + ")", "<code>" + esc(r.correlationId())
                + "</code>");
        fact(h, "Workbench version", esc(r.workbenchVersion()));
        fact(h, "Generated", utc(r.generatedAt()));
        h.append("</dl>\n");
        FailingCall.of(r).ifPresent(call -> htmlFailingCall(h, call));

        h.append("<section aria-labelledby=\"timeline-h\">\n<h2 id=\"timeline-h\">Step timeline</h2>\n<ol class=\"timeline\">\n");
        int n = 1;
        for (RunReport.Step step : r.steps()) {
            String tone = switch (step.status()) {
                case "passed" -> "pass";
                case "failed" -> "fail";
                default -> "skip";
            };
            h.append("<li class=\"step ").append(esc(step.status())).append("\">")
                    .append(icon(iconFor(tone), 18, "ic-" + tone))
                    .append("<span class=\"t\">").append(n++).append(". ").append(esc(step.title()))
                    .append(" <span class=\"chip ").append(tone).append("\">").append(esc(step.status()))
                    .append("</span></span><span class=\"ms\">");
            if (!step.status().equals("skipped")) {
                h.append(step.elapsedMs()).append(" ms");
            }
            h.append("</span><span class=\"s\">").append(esc(orDash(step.summary()))).append("</span>");
            for (String exchange : step.exchanges()) {
                h.append("<code class=\"x\">").append(esc(exchange)).append("</code>");
            }
            h.append("</li>\n");
        }
        h.append("</ol>\n</section>\n");

        h.append("<section aria-labelledby=\"findings-h\">\n<h2 id=\"findings-h\">Findings</h2>\n");
        for (Severity severity : r.counts().keySet()) {
            String tone = tone(severity);
            for (Finding f : r.findings()) {
                if (f.severity() != severity) {
                    continue;
                }
                h.append("<article class=\"finding ").append(severity).append("\">\n<div class=\"fhead\"><span class=\"chip ")
                        .append(tone).append("\">").append(icon(iconFor(tone), 12, "")).append(word(severity.name()))
                        .append("</span><h3>").append(esc(f.title())).append("</h3><code class=\"cid\">")
                        .append(esc(f.checkId())).append("</code></div>\n<div class=\"fbody\">\n");
                if (f.explanation() != null) {
                    h.append("<p>").append(esc(f.explanation())).append("</p>\n");
                }
                if (f.evidence() != null && !f.evidence().isBlank()) {
                    h.append("<p class=\"label\">Evidence (redacted)</p>\n<pre>").append(esc(f.evidence().strip()))
                            .append("</pre>\n");
                }
                if (f.suggestedFix() != null) {
                    h.append("<div class=\"fix\">").append(icon(ICON_FIX, 18, "")).append("<p><b>Fix</b> ")
                            .append(esc(f.suggestedFix())).append("</p></div>\n");
                }
                h.append("</div>\n</article>\n");
            }
        }
        h.append("</section>\n");
        h.append("<footer>").append(esc(r.disclaimer())).append("<br>Generated ").append(utc(r.generatedAt()))
                .append(" by payer onboarding workbench ").append(esc(r.workbenchVersion())).append(".</footer>\n");
        h.append("</main>\n</body>\n</html>\n");
        return h.toString();
    }

    /** The answer first: icon and word, the headline, where the flow broke and the counts. */
    private static void htmlVerdict(StringBuilder h, RunReport r) {
        String status = r.verdict().status();
        String tone = switch (status) {
            case "PASS" -> "pass";
            case "FAIL" -> "fail";
            default -> "warn";
        };
        h.append("<section class=\"verdict ").append(esc(status)).append("\" aria-labelledby=\"verdict-h\">\n")
                .append("<div class=\"vband ").append(tone).append("\">").append(icon(iconFor(tone), 34, ""))
                .append("<div><h2 id=\"verdict-h\">Verdict: ").append(esc(word(status))).append("</h2>\n<p class=\"vhead\">")
                .append(esc(r.verdict().headline())).append("</p></div></div>\n<div class=\"vfoot\">");
        if (r.verdict().brokeAt() != null) {
            h.append("<span>Broke at <strong>").append(esc(r.verdict().brokeAt())).append("</strong></span>");
        }
        r.counts().forEach((severity, count) -> h.append("<span class=\"chip ").append(tone(severity)).append("\">")
                .append(count).append(' ').append(severity.name().toLowerCase(Locale.ROOT)).append("</span>"));
        h.append("</div>\n</section>\n");
    }

    /** Reproduce with curl first, then the request beside the response on screen. */
    private static void htmlFailingCall(StringBuilder h, FailingCall call) {
        h.append("<section class=\"failing-call\" aria-labelledby=\"call-h\">\n<h2 id=\"call-h\">Failing call</h2>\n")
                .append("<p>The last call of the <strong>").append(esc(call.stepTitle())).append("</strong> step. ")
                .append(esc(FAILING_CALL_NOTE)).append("</p>\n");
        h.append("<p class=\"call-line\"><span class=\"method\">").append(esc(call.method())).append("</span><span>")
                .append(esc(call.url())).append("</span><span class=\"chip ")
                .append(call.status().startsWith("HTTP 2") ? "pass" : "fail").append("\">").append(esc(call.status()))
                .append("</span>");
        if (call.latencyMs() != null) {
            h.append("<span class=\"ms\">").append(call.latencyMs()).append(" ms</span>");
        }
        h.append("</p>\n");
        h.append("<div class=\"curl\">\n<p class=\"label\">Reproduce with curl</p>\n<p class=\"muted\">")
                .append(esc(curlNote(call))).append("</p>\n<pre>").append(esc(call.curl())).append("</pre>\n</div>\n");
        h.append("<div class=\"two\">\n<div>\n");
        htmlBlock(h, "Request headers", String.join("\n", call.requestHeaders()));
        htmlBody(h, "Request body", call.requestBody());
        h.append("</div>\n<div>\n");
        if (call.transportError() != null) {
            htmlBlock(h, "Transport error", call.transportError());
        }
        htmlBlock(h, "Response headers", String.join("\n", call.responseHeaders()));
        htmlBody(h, "Response body", call.responseBody());
        h.append("</div>\n</div>\n</section>\n");
    }

    private static void htmlBody(StringBuilder h, String label, FailingCall.Body body) {
        if (body == null) {
            htmlBlock(h, label, "");
            return;
        }
        h.append("<p class=\"label\">").append(esc(label)).append("</p>\n<pre>")
                .append(esc(body.text().stripTrailing())).append("</pre>\n");
        if (body.truncated()) {
            h.append("<p class=\"muted\">").append(esc(FailingCall.TRUNCATED_NOTE)).append("</p>\n");
        }
    }

    private static void htmlBlock(StringBuilder h, String label, String text) {
        h.append("<p class=\"label\">").append(esc(label)).append("</p>\n");
        if (text.isBlank()) {
            h.append("<p class=\"muted\">None</p>\n");
            return;
        }
        h.append("<pre>").append(esc(text)).append("</pre>\n");
    }

    private static void fact(StringBuilder h, String label, String valueHtml) {
        h.append("<div><dt>").append(esc(label)).append("</dt><dd>").append(valueHtml).append("</dd></div>\n");
    }

    /** An ISO-8601 instant as UTC to the second, keeping the full value in {@code datetime} for log matching. */
    static String utc(String iso) {
        if (iso == null || iso.isBlank()) {
            return "—";
        }
        try {
            return "<time datetime=\"" + esc(iso) + "\">" + UTC_SECONDS.format(Instant.parse(iso)) + "</time>";
        } catch (DateTimeParseException e) {
            return esc(iso);
        }
    }

    private static String icon(String paths, int size, String cssClass) {
        return "<svg" + (cssClass.isEmpty() ? "" : " class=\"" + cssClass + "\"") + " width=\"" + size + "\" height=\""
                + size + "\" viewBox=\"0 0 20 20\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\""
                + " stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">" + paths + "</svg>";
    }

    private static String iconFor(String tone) {
        return switch (tone) {
            case "pass" -> ICON_PASS;
            case "fail" -> ICON_FAIL;
            case "warn" -> ICON_WARN;
            case "info" -> ICON_INFO;
            default -> ICON_SKIP;
        };
    }

    private static String tone(Severity severity) {
        return severity.name().toLowerCase(Locale.ROOT);
    }

    /** {@code PASS_WITH_WARNINGS} as {@code Pass with warnings}. */
    private static String word(String constant) {
        String lower = constant.toLowerCase(Locale.ROOT).replace('_', ' ');
        return Character.toUpperCase(lower.charAt(0)) + lower.substring(1);
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

    /**
     * Inline so the file stands alone. The workbench app's tokens, with dark mode on screen only: print is always
     * light. Print keeps headings with the block after them and lets long {@code pre} blocks split across pages.
     */
    private static final String CSS = """
            :root{--bg:#fff;--ink:#24362e;--muted:#54604f;--line:#d9ded1;--green:#375d46;--bad:#9a3b2b;--bad-bg:#f7e6e1;\
            --warn:#7a5a24;--warn-bg:#f6ecd8;--info:#2f5873;--info-bg:#e3edf3;--pass:#375d46;--pass-bg:#e3eee5;\
            --code:#f4f2ec;--mono:Consolas,"SFMono-Regular",Menlo,monospace;--serif:Georgia,"Times New Roman",serif;\
            color-scheme:light}
            @media screen and (prefers-color-scheme:dark){:root{--bg:#151b18;--ink:#e4e9e2;--muted:#a4b0a2;--line:#34413a;\
            --green:#7fb894;--bad:#f0907d;--bad-bg:#3a2420;--warn:#e3c07c;--warn-bg:#372d1b;--info:#8fc1e3;\
            --info-bg:#1d2e3a;--pass:#8fcfa3;--pass-bg:#1d3226;--code:#1c2420;color-scheme:dark}}
            *{box-sizing:border-box}
            body{margin:0;color:var(--ink);background:var(--bg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
            main{max-width:880px;margin:0 auto;padding:40px 24px 48px;display:flex;flex-direction:column;gap:22px}
            p{margin:0}
            .kicker{font:600 11px var(--mono);letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin:0 0 4px}
            h1{font:32px/1.2 var(--serif);margin:0;font-weight:400;text-wrap:balance}
            h2{font:22px/1.3 var(--serif);margin:0 0 10px;font-weight:400;padding-bottom:6px;border-bottom:1px solid var(--line)}
            h3{font-size:16px;margin:0}
            code,pre{font-family:var(--mono)}.facts code{font-size:13px}
            .sub{font-size:14px;color:var(--muted);margin-top:6px;overflow-wrap:anywhere}
            .muted{color:var(--muted);font-size:14px}
            .disclaimer{display:flex;gap:10px;align-items:flex-start;font-size:13.5px;background:var(--warn-bg);\
            border:1px solid var(--warn);border-radius:6px;padding:10px 12px}
            .disclaimer svg{flex:none;color:var(--warn);margin-top:2px}
            .verdict{border:1px solid var(--line);border-radius:8px;overflow:hidden}
            .vband{display:flex;gap:14px;align-items:flex-start;padding:16px 18px}
            .vband svg{flex:none}
            .vband.fail{background:var(--bad-bg)}.vband.fail svg,.vband.fail h2{color:var(--bad)}
            .vband.warn{background:var(--warn-bg)}.vband.warn svg,.vband.warn h2{color:var(--warn)}
            .vband.pass{background:var(--pass-bg)}.vband.pass svg,.vband.pass h2{color:var(--pass)}
            .vband h2{font:700 13px var(--mono);letter-spacing:1px;text-transform:uppercase;border:0;padding:0;margin:0}
            .vhead{font:20px/1.35 var(--serif);margin-top:2px}
            .vfoot{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;padding:10px 18px;font-size:14px}
            .chip{display:inline-flex;align-items:center;gap:4px;font:700 11px/1.6 var(--mono);letter-spacing:.5px;\
            text-transform:uppercase;padding:0 8px;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
            .chip.pass{color:var(--pass);background:var(--pass-bg)}.chip.fail{color:var(--bad);background:var(--bad-bg)}
            .chip.warn{color:var(--warn);background:var(--warn-bg)}.chip.info{color:var(--info);background:var(--info-bg)}
            .chip.skip{color:var(--muted)}
            .facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(360px,100%),1fr));gap:0 28px;margin:0}
            .facts div{display:grid;grid-template-columns:170px minmax(0,1fr);gap:12px;padding:7px 0;border-bottom:1px solid var(--line)}
            .facts dt{color:var(--muted);font-size:14px}.facts dd{margin:0;overflow-wrap:anywhere}
            .call-line{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;font:14px var(--mono);overflow-wrap:anywhere;margin:8px 0 14px}
            .method{font:700 11px var(--mono);padding:1px 6px;border-radius:4px;background:var(--code);border:1px solid var(--line)}
            .label{font:700 11px var(--mono);letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin:12px 0 4px}
            pre{font-size:12.5px;line-height:1.5;background:var(--code);border:1px solid var(--line);border-radius:6px;\
            padding:10px 12px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
            .curl{border:1px solid var(--green);border-radius:8px;padding:12px 14px}
            .curl .label{margin-top:0;color:var(--green)}.curl .muted{margin-bottom:6px}
            .two{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:0 20px}
            .two>div{min-width:0}
            .timeline{list-style:none;margin:0;padding:0}
            .step{display:grid;grid-template-columns:22px minmax(0,1fr) auto;gap:2px 12px;padding:9px 0;\
            border-bottom:1px solid var(--line);align-items:start}
            .step:last-child{border-bottom:0}
            .step svg{grid-row:span 2;margin-top:2px}
            .step .t{font-weight:600;display:flex;flex-wrap:wrap;gap:4px 8px;align-items:center}
            .step .s{font-size:14px;color:var(--muted);grid-column:2/4}
            .step .x{grid-column:2/4;font-size:12.5px;color:var(--muted);overflow-wrap:anywhere}
            .ms{font:13px var(--mono);color:var(--muted);white-space:nowrap}
            .ic-pass{color:var(--pass)}.ic-fail{color:var(--bad)}.ic-skip{color:var(--muted)}
            .finding{border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:12px}
            .fhead{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:center;padding:10px 14px}
            .finding.FAIL .fhead{background:var(--bad-bg)}.finding.WARN .fhead{background:var(--warn-bg)}
            .finding.INFO .fhead{background:var(--info-bg)}.finding.PASS .fhead{background:var(--pass-bg)}
            .cid{font-size:12px;color:var(--muted)}
            .fbody{padding:10px 14px 14px;display:flex;flex-direction:column;gap:8px}
            .fbody .label{margin:4px 0 0}
            .fix{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:6px;padding:10px 12px}
            .fix svg{flex:none;color:var(--green);margin-top:2px}
            .fix b{display:block;font:700 11px var(--mono);letter-spacing:1px;text-transform:uppercase;color:var(--green)}
            footer{font-size:12.5px;color:var(--muted);border-top:1px solid var(--line);padding-top:12px}
            @media (max-width:600px){main{padding:24px 16px 32px}h1{font-size:26px}\
            .facts div{grid-template-columns:1fr;gap:0}.vband,.vfoot{padding-left:14px;padding-right:14px}}
            @page{margin:.75in}
            @media print{body{font-size:11pt}main{max-width:none;padding:0;gap:18px}
            *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
            .two{grid-template-columns:1fr}
            h2,h3,.label,.fhead,.call-line,.curl .muted{break-after:avoid}
            .verdict,.facts div,.step,.fix,.disclaimer,.curl pre,footer{break-inside:avoid}
            pre,.finding,.curl{break-inside:auto}}
            """;
}
