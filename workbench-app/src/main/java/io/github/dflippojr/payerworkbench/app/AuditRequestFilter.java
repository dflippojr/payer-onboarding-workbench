package io.github.dflippojr.payerworkbench.app;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/** Audits run HTTP operations even when MVC cannot deserialize the body. */
@Component
public class AuditRequestFilter extends OncePerRequestFilter {
    private final AuditLog log;
    public AuditRequestFilter(AuditLog log) { this.log = log; }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        boolean post = request.getMethod().equals("POST") && path.equals("/api/runs");
        String action = action(request.getMethod(), path);
        if (action == null) { chain.doFilter(request, response); return; }
        AuditContext context = new AuditContext(log);
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
                        path.equals("/api/runs") && !post ? "run_history" : "run", context.runId, context.metadata(status));
            } finally { AuditContext.clear(); }
        }
    }

    private static String action(String method, String path) {
        if (method.equals("POST") && path.equals("/api/runs")) { return "run.completed"; }
        if (!method.equals("GET")) { return null; }
        if (path.equals("/api/runs")) { return "run_history.read"; }
        if (path.matches("/api/runs/[^/]+/report")) { return "report.rendered"; }
        return path.matches("/api/runs/[^/]+") ? "run.read" : null;
    }
}
