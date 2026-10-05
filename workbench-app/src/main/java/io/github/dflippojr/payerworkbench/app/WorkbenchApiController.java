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
    private final String version = workbenchVersion();

    public WorkbenchApiController(SyntheticPayers payers, SampleCatalog samples, OnboardingRunner runner, RunStore runs) {
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

    @GetMapping("/samples")
    public List<SampleMetadata> samples() {
        return samples.list();
    }

    @PostMapping("/runs")
    public OnboardingRun run(@RequestBody RunRequest request) {
        if (request.payerId() == null || request.sampleId() == null) {
            throw new IllegalArgumentException("payerId and sampleId are required");
        }
        OnboardingRun run = runner.run(request);
        runs.save(run);
        return run;
    }

    @GetMapping("/runs/{id}")
    public OnboardingRun run(@PathVariable String id) {
        return runs.find(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No run " + id));
    }

    /** A shareable, redacted report of a run as {@code md}, {@code html} or {@code json}. */
    @GetMapping("/runs/{id}/report")
    public ResponseEntity<String> report(@PathVariable String id, @RequestParam(defaultValue = "html") String format) {
        ReportRenderer.Format f = ReportRenderer.Format.fromId(format)
                .orElseThrow(() -> new IllegalArgumentException("format must be md, html or json"));
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

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail badRequest(IllegalArgumentException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }
}
