package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Semaphore;

/**
 * Runs one onboarding attempt against a synthetic payer or a custom endpoint, the way an integration
 * engineer would: resolve the connection, discover services, authenticate, send a sample hook request,
 * parse the response, then explain what was seen. This is the facade the API and the first-run warm-up call:
 * {@link RunRequestValidator} checks the request, {@link PayerLease} holds a synthetic payer and its faults for
 * the run, {@link CustomEndpointSetup} prepares a custom endpoint, and {@link RunAttempt} runs the steps.
 *
 * <p>Runs against the same payer are serialized so one run's faults never leak into another's. A run waits its turn
 * for at most {@code workbench.request-timeout} and is then refused, and a {@code slow-response} delay
 * longer than {@link WorkbenchProperties#maxSlowResponseDelay()} is refused before it can hold the payer.
 *
 * <p>The run id is also the run's correlation id: it is sent to the payer as
 * {@value RequestIdClient#HEADER} on every call, held in the logging MDC as
 * {@value #MDC_RUN_ID} while the run executes, and each step is logged at INFO as one
 * line (run id, payer, step, status, milliseconds; never a request or response body).
 */
@Service
public class OnboardingRunner {

    public static final String RESOLVE = "resolve-connection";
    public static final String DISCOVERY = "discovery";
    public static final String AUTHENTICATE = "authenticate";
    public static final String HOOK_REQUEST = "hook-request";
    public static final String PARSE_RESPONSE = "parse-response";
    public static final String DIAGNOSTICS = "diagnostics";
    /** Workbench-level finding for a run that found no connection record (not in the diagnostics catalog). */
    public static final String CONNECTION_RECORD_CHECK = "connection.record";
    /** A step failed and no other check explains it. */
    public static final String STEP_FAILED_CHECK = "run.step-failed";
    /** The discovery step's summary when services holds entries the SDK cannot map to a service. */
    static final String UNREADABLE_SERVICES = "The payer's discovery document lists services that are not CDS "
            + "service objects; see the discovery.services finding";
    /**
     * A payer response ran past {@code workbench.max-response-bytes}, so the workbench stopped reading it,
     * or held more than {@code workbench.max-response-json-values}, so it was not parsed.
     */
    public static final String RESPONSE_TOO_LARGE_CHECK = "run.response-too-large";
    /** A hook response held more than {@link #MAX_CARDS} cards, so the workbench did not read them one by one. */
    public static final String TOO_MANY_CARDS_CHECK = "run.too-many-cards";
    /**
     * Cards a hook response may hold before the parse step fails without building a view of each.
     * A byte limit alone does not bound the work: 4 MiB of empty objects is 1.4 million cards.
     */
    static final int MAX_CARDS = 1000;
    /** Cards, coverage-information entries and discovered services shown in a step's details; the rest are counted. */
    static final int MAX_VIEWS = 100;
    /** Cards with missing fields named in the parse step's summary; the rest are counted. */
    static final int MAX_PROBLEMS = 5;
    /** Prefetch keys and {@code docNeeded} entries shown per service or coverage entry; the rest are counted. */
    static final int MAX_LIST_ENTRIES = 20;
    static final List<String> STEP_ORDER = List.of(RESOLVE, DISCOVERY, AUTHENTICATE, HOOK_REQUEST, PARSE_RESPONSE);
    /** MDC keys set for the length of a run. */
    static final String MDC_RUN_ID = "runId";
    static final String MDC_PAYER = "payer";

    private final SyntheticPayers payers;
    private final WorkbenchProperties properties;
    private final RunRequestValidator validator;
    private final PayerLease.Locks leases;
    private final RunAttempt.Services services;
    /** Custom-endpoint runs in flight; see {@link WorkbenchProperties#maxConcurrentRuns()}. */
    private final Semaphore customRuns;

    public OnboardingRunner(SyntheticPayers payers, SampleCatalog samples, WorkbenchProperties properties,
                            RunMetrics metrics) {
        this.payers = payers;
        this.properties = properties;
        this.validator = new RunRequestValidator(payers, samples, properties);
        this.leases = new PayerLease.Locks(properties.requestTimeout());
        this.services = new RunAttempt.Services(payers, samples, properties, metrics, new ObjectMapper());
        this.customRuns = new Semaphore(properties.maxConcurrentRuns());
    }

    /**
     * Runs the steps for {@code request}.
     *
     * @throws RunRejection       if the request is refused before any run starts: a missing or unknown payer, sample
     *                            or fault id, a {@code slow-response} delay past
     *                            {@link WorkbenchProperties#maxSlowResponseDelay()}, a refused connection edit or
     *                            custom endpoint; it carries the audit reason code and the HTTP status
     * @throws PayerBusyException if another run held the synthetic payer for all of {@code workbench.request-timeout}
     * @throws RunsBusyException  if {@code workbench.max-concurrent-runs} custom runs are already in flight
     */
    public OnboardingRun run(RunRequest request) {
        return run(request, true);
    }

    /**
     * Runs one onboarding against a synthetic payer to load classes and set up TLS, Jackson and the
     * SDK, so the first user run is not the one that pays for it. The run is not recorded in the
     * metrics and the caller discards the result.
     */
    OnboardingRun warmUp(RunRequest request) {
        return run(request, false);
    }

    /**
     * Runs inside the caller's audit scope. A run started outside any HTTP request or job is recorded as
     * a programmatic call by an unknown actor, never as an owner operation; the warm-up is the app itself.
     */
    private OnboardingRun run(RunRequest request, boolean recordMetrics) {
        if (AuditContext.current() != null) {
            return runScoped(request, recordMetrics);
        }
        AuditContext fallback = recordMetrics
                ? AuditContext.actor(payers.audit(), "unknown", null, "programmatic")
                : AuditContext.actor(payers.audit(), "system", "first-run-warmup", "job");
        AuditContext.bind(fallback);
        try {
            return runScoped(request, recordMetrics);
        } finally {
            AuditContext.clear();
        }
    }

    AuditLog audit() {
        return payers.audit();
    }

    private OnboardingRun runScoped(RunRequest request, boolean recordMetrics) {
        ValidatedRun run = validator.validate(request);
        return run.custom() != null ? runCustom(run) : runSynthetic(run, recordMetrics);
    }

    private OnboardingRun runSynthetic(ValidatedRun validated, boolean recordMetrics) {
        RunRequest request = validated.request();
        MockPayer payer = validated.payer();
        String runId = UUID.randomUUID().toString();
        AuditContext audit = AuditContext.current();
        return leases.hold(request.payerId(), payer, lease -> {
            if (audit != null) { audit.runId = runId; }
            try (MDC.MDCCloseable id = MDC.putCloseable(MDC_RUN_ID, runId);
                 MDC.MDCCloseable payerId = MDC.putCloseable(MDC_PAYER, request.payerId())) {
                lease.setUp(validated.faults(), validated.slowResponseDelay());
                try (HttpClient http = HttpClient.newBuilder()
                        .sslContext(payers.tls().clientContext())
                        .connectTimeout(Duration.ofSeconds(5))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build()) {
                    return new RunAttempt(services, runId, request, validated.sample(), http, payers.credentials(),
                            null, recordMetrics).run();
                }
            }
        });
    }

    /**
     * Runs the steps against a payer the user named. The destination was checked when the request was validated,
     * and the credential lives in a store made for this run alone, so it is gone when the run returns.
     *
     * @throws RunsBusyException if {@code workbench.max-concurrent-runs} custom runs are already in flight
     */
    private OnboardingRun runCustom(ValidatedRun validated) {
        RunRequest request = validated.request();
        CustomEndpointSetup custom = validated.custom();
        AuditContext audit = AuditContext.current();
        if (!customRuns.tryAcquire()) {
            custom.forgetCredential();
            throw new RunsBusyException(properties.maxConcurrentRuns());
        }

        String runId = UUID.randomUUID().toString();
        if (audit != null) { audit.runId = runId; }
        try (MDC.MDCCloseable id = MDC.putCloseable(MDC_RUN_ID, runId);
             MDC.MDCCloseable payerId = MDC.putCloseable(MDC_PAYER, request.payerId());
             HttpClient http = HttpClient.newBuilder()
                     .connectTimeout(Duration.ofSeconds(5))
                     .followRedirects(HttpClient.Redirect.NEVER)
                     .build()) {
            return new RunAttempt(services, runId, request, validated.sample(), custom.guard().wrap(http),
                    custom.credentials(), custom.record(), true).run();
        } finally {
            custom.forgetCredential();
            customRuns.release();
        }
    }

    /** See {@link RunRequestValidator#withSuffix}. */
    static String withSuffix(String baseUrl, String suffix) {
        return RunRequestValidator.withSuffix(baseUrl, suffix);
    }

    /** See {@link RunAttempt#epochSeconds}. */
    static Instant epochSeconds(JsonNode json, String field) {
        return RunAttempt.epochSeconds(json, field);
    }
}
