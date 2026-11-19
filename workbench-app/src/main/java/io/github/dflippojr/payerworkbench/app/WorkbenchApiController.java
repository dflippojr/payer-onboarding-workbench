package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.RedactedConnection;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import io.github.dflippojr.payerworkbench.samples.SampleMetadata;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/** The workbench REST API under {@code /api}. */
@RestController
@RequestMapping("/api")
public class WorkbenchApiController {

    /** A synthetic payer, its stored connections (redacted) and what a run may change. */
    public record PayerView(
            String payerId,
            String displayName,
            String advertisedIgVersion,
            List<RedactedConnection> connections,
            List<String> editableSettings,
            List<String> faults
    ) {
    }

    private final SyntheticPayers payers;
    private final SampleCatalog samples;
    private final OnboardingRunner runner;
    private final RunStore runs;
    private final WorkbenchProperties properties;
    private final String version = workbenchVersion();

    public WorkbenchApiController(SyntheticPayers payers, SampleCatalog samples, OnboardingRunner runner, RunStore runs,
                                  WorkbenchProperties properties) {
        this.properties = properties;
        this.payers = payers;
        this.samples = samples;
        this.runner = runner;
        this.runs = runs;
    }

    @GetMapping("/payers")
    public List<PayerView> payers() {
        List<String> faults = Arrays.stream(Fault.values()).map(Fault::id).toList();
        return payers.payerIds().stream().map(id -> {
            MockPayer payer = payers.payer(id).orElseThrow();
            List<ConnectionRecord> records = payers.store().findByPayerId(id);
            List<String> editable = List.of("baseUrlSuffix", "igVersion", "clientId");
            return new PayerView(id, payer.displayName(), payer.igVersion(),
                    records.stream().map(RedactedConnection::of).toList(), editable, faults);
        }).toList();
    }

    /** What this deployment allows; the UI shows the custom endpoint form only when it is on. */
    @GetMapping("/features")
    public Map<String, Boolean> features() {
        return Map.of("customEndpoints", properties.customEndpoints().enabled());
    }

    @GetMapping("/samples")
    public List<SampleMetadata> samples() {
        return samples.list();
    }

    @PostMapping("/runs")
    public OnboardingRun run(@RequestBody RunRequest request) {
        auditIdentity(request);
        OnboardingRun run = runner.run(request);
        runs.save(run);
        AuditContext audit = AuditContext.current();
        if (audit != null) { audit.verdict = RunVerdict.of(run).status(); }
        return run;
    }

    @GetMapping("/runs")
    public List<RunSummary> recentRuns() {
        return runs.list();
    }

    @GetMapping("/runs/{id}")
    public OnboardingRun run(@PathVariable String id) {
        OnboardingRun run = runs.find(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No run " + id));
        AuditContext audit = AuditContext.current();
        if (audit != null) { audit.runId = run.runId(); }
        return run;
    }

    /** A shareable, redacted report of a run as {@code md}, {@code html} or {@code json}. */
    @GetMapping("/runs/{id}/report")
    public ResponseEntity<String> report(@PathVariable String id, @RequestParam(defaultValue = "html") String format) {
        AuditContext audit = AuditContext.current();
        if (audit != null) {
            audit.runId = runs.find(id).map(OnboardingRun::runId).orElse(null);
            audit.reportFormat = ReportRenderer.Format.fromId(format).map(ReportRenderer.Format::extension).orElse(null);
        }
        ReportRenderer.Format f = ReportRenderer.Format.fromId(format)
                .orElseThrow(() -> new RunRejection("invalid_format", "format must be md, html or json"));
        OnboardingRun run = run(id);
        MockPayer payer = payers.payer(run.payerId()).orElse(null);
        RunReport report = RunReport.of(run, payer == null ? null : payer.displayName(),
                payer == null ? null : payer.igVersion(), Instant.now(), version);
        String filename = "onboarding-report-" + run.payerId() + "-" + run.runId() + "." + f.extension();
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(f.mediaType()))
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.inline().filename(filename, StandardCharsets.UTF_8).build().toString())
                .body(ReportRenderer.render(report, f));
    }

    /**
     * Fills the audit trail's payer, sample and environment from the request before the run is validated, so a
     * refused request carries what it named and the events of a run that starts carry them too. Only a payer and a
     * sample the workbench knows are copied; an unknown id never reaches the trail. The reason for a refusal is
     * written by {@link #rejected}, not here.
     */
    private void auditIdentity(RunRequest request) {
        AuditContext audit = AuditContext.current();
        if (audit == null) { return; }
        audit.environment = request.environment();
        audit.payerId = request.customEndpoint() != null ? RunRequest.CUSTOM_PAYER_ID
                : (request.payerId() != null && payers.payerIds().contains(request.payerId())) ? request.payerId() : null;
        audit.sampleId = samples.list().stream().filter(s -> s.id().equals(request.sampleId()))
                .map(SampleMetadata::id).findFirst().orElse(null);
    }

    /** The version from {@code META-INF/build-info.properties}, written by the Spring Boot Maven plugin. */
    private static String workbenchVersion() {
        try (InputStream in = WorkbenchApiController.class.getResourceAsStream("/META-INF/build-info.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                return props.getProperty("build.version", "unknown");
            }
        } catch (IOException e) {
            // fall through
        }
        String manifest = WorkbenchApiController.class.getPackage().getImplementationVersion();
        return manifest == null ? "unknown" : manifest;
    }

    /**
     * The one place a refused run or report request gets its audit reason: the {@link RunRejection} carries it with
     * the status and the message, so the answer and the audit trail can't disagree.
     */
    @ExceptionHandler(RunRejection.class)
    ResponseEntity<ProblemDetail> rejected(RunRejection e) {
        AuditContext audit = AuditContext.current();
        if (audit != null) { audit.reasonCode = e.reasonCode(); }
        return ResponseEntity.status(e.status()).headers(e.headers())
                .body(ProblemDetail.forStatusAndDetail(e.status(), e.getMessage()));
    }

    /**
     * Any other {@link IllegalArgumentException}, one no rule planned for: still a 400 with its message, which
     * {@link AuditRequestFilter} audits as {@code invalid_body}.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail badRequest(IllegalArgumentException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    /** A run body that can't be bound. {@link AuditRequestFilter} audits the 400 as {@code invalid_body}. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    ProblemDetail unreadableBody(HttpMessageNotReadableException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, RunBodyProblem.describe(e.getCause()));
    }
}
