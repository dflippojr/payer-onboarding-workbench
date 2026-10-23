package io.github.dflippojr.payerworkbench.app;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

/** Audits run HTTP operations even when MVC cannot deserialize the body. */
@Component
public class AuditRequestFilter extends OncePerRequestFilter {
    private static final List<String> RUNS = List.of("/", "api", "/", "runs");
    private final AuditLog log;
    private final InternalRequestToken internal;

    public AuditRequestFilter(AuditLog log) { this(log, new InternalRequestToken()); }

    @org.springframework.beans.factory.annotation.Autowired
    AuditRequestFilter(AuditLog log, InternalRequestToken internal) {
        this.log = log;
        this.internal = internal;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        List<String> path = elements(request);
        boolean history = path.equals(RUNS);
        boolean post = request.getMethod().equals("POST") && history;
        String action = action(request.getMethod(), path);
        if (action == null) { chain.doFilter(request, response); return; }
        AuditContext context = new AuditContext(log);
        // Only the app's own warm-up request holds the current single-use value; any other header is ignored.
        boolean canonical = request.getRequestURI().substring(request.getContextPath().length()).equals("/api/runs");
        if (post && canonical && internal.consume(request.getHeader(InternalRequestToken.HEADER))) {
            context.actorType = "system";
            context.actorId = "first-run-warmup";
            context.source = "job";
        }
        AuditContext.bind(context);
        boolean failed = false;
        try {
            if (post) { log.emit(context, "run.requested", "started", "run", null, context.metadata(null)); }
            chain.doFilter(request, response);
        } catch (IOException | ServletException | RuntimeException e) {
            failed = true;
            throw e;
        } finally {
            try {
                int status = failed ? 500 : response.getStatus();
                if (status >= 400 && context.reasonCode == null) {
                    context.reasonCode = status == 404 ? "not_found" : status == 400 ? "invalid_body" : "request_failed";
                }
                log.emit(context, action, status < 400 ? "success" : "rejected",
                        history && !post ? "run_history" : "run", context.runId, context.metadata(status));
            } finally { AuditContext.clear(); }
        }
    }

    /**
     * The path as MVC's pattern matcher sees it: separators as {@code "/"}, segments decoded with {@code ;}
     * parameters removed, so {@code /api;a/run%73} audits like {@code /api/runs}.
     */
    static List<String> elements(HttpServletRequest request) {
        return RequestPath.parse(request.getRequestURI(), request.getContextPath()).pathWithinApplication().elements()
                .stream().map(e -> e instanceof PathContainer.PathSegment s ? s.valueToMatch() : e.value()).toList();
    }

    private static String action(String method, List<String> path) {
        if (path.size() < 4 || !path.subList(0, 4).equals(RUNS)) { return null; }
        if (path.size() == 4) { return method.equals("POST") ? "run.completed" : method.equals("GET") ? "run_history.read" : null; }
        // Elements alternate separator and segment, so index 5 is the run id unless the path has an empty segment.
        if (!method.equals("GET") || path.size() < 6 || path.get(5).equals("/")) { return null; }
        if (path.size() == 6) { return "run.read"; }
        return path.size() == 8 && path.get(6).equals("/") && path.get(7).equals("report") ? "report.rendered" : null;
    }
}
