package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.Card;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.SystemAction;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.CdsServiceDescriptor;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.RedactedConnection;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.core.TextLimit;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import io.github.dflippojr.payerworkbench.diagnostics.DiagnosticEngine;
import io.github.dflippojr.payerworkbench.diagnostics.DiagnosticsConfig;
import io.github.dflippojr.payerworkbench.diagnostics.DiscoveryServicesCheck;
import io.github.dflippojr.payerworkbench.core.AuditEvent;
import io.github.dflippojr.payerworkbench.mock.Fault;
import io.github.dflippojr.payerworkbench.mock.FaultSettings;
import io.github.dflippojr.payerworkbench.mock.MockPayer;
import io.github.dflippojr.payerworkbench.samples.PrefetchVariant;
import io.github.dflippojr.payerworkbench.samples.Sample;
import io.github.dflippojr.payerworkbench.samples.SampleCatalog;
import io.github.dflippojr.payerworkbench.samples.SampleMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Runs one onboarding attempt against a synthetic payer, the way an integration
 * engineer would: resolve the connection, discover services, authenticate, send a
 * sample hook request, parse the response, then explain what was seen.
 *
 * <p>The first step that fails stops the attempt; the steps after it are recorded as
 * skipped, and diagnostics run on whatever was observed. Every HTTP exchange is
 * recorded through {@link ExchangeRecorder}, so step details never carry a secret.
 *
 * <p>Faults are switched on at the mock payer for the length of one run. Runs against
 * the same payer are serialized so one run's faults never leak into another's. A run waits its turn
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

    private static final Logger LOG = LoggerFactory.getLogger(OnboardingRunner.class);

    private final SyntheticPayers payers;
    private final SampleCatalog samples;
    private final WorkbenchProperties properties;
    private final RunMetrics metrics;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();
    /** Custom-endpoint runs in flight; see {@link WorkbenchProperties#maxConcurrentRuns()}. */
    private final Semaphore customRuns;

    public OnboardingRunner(SyntheticPayers payers, SampleCatalog samples, WorkbenchProperties properties,
                            RunMetrics metrics) {
        this.payers = payers;
        this.samples = samples;
        this.properties = properties;
        this.metrics = metrics;
        this.customRuns = new Semaphore(properties.maxConcurrentRuns());
    }

    /**
     * Runs the steps for {@code request}.
     *
     * @throws IllegalArgumentException if the payer, sample or a fault id is unknown, or the
     *                                  {@code slow-response} delay is past {@link WorkbenchProperties#maxSlowResponseDelay()}
     * @throws PayerBusyException       if another run held the synthetic payer for all of {@code workbench.request-timeout}
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
        if (request.customEndpoint() != null) {
            return runCustom(request);
        }
        MockPayer payer = payers.payer(request.payerId())
                .orElseThrow(() -> new IllegalArgumentException("Unknown payerId: " + request.payerId()));
        SampleMetadata sample = samples.list().stream()
                .filter(s -> s.id().equals(request.sampleId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown sampleId: " + request.sampleId()));
        List<Fault> faults = request.faults().stream()
                .map(id -> Fault.fromId(id).orElseThrow(() -> new IllegalArgumentException("Unknown fault: " + id)))
                .toList();
        checkSlowResponseDelay(request);
        checkSuffix(request, payers.store().findByPayerIdAndEnvironment(request.payerId(), request.environment())
                .map(ConnectionRecord::baseUrl).orElse(null));

        String runId = UUID.randomUUID().toString();
        AuditContext audit = AuditContext.current();
        // Fair, so runs get the payer in the order they asked for it. The wait is at most request-timeout, the
        // longest one call of the run ahead can hold the payer, so a queue of slow runs refuses the runs behind
        // it instead of stalling them.
        ReentrantLock lock = locks.computeIfAbsent(request.payerId(), id -> new ReentrantLock(true));
        boolean held;
        try {
            held = lock.tryLock(properties.requestTimeout().toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            held = false;
        }
        if (!held) {
            throw payerBusy(audit, request.payerId());
        }
        if (audit != null) { audit.runId = runId; }
        try (MDC.MDCCloseable id = MDC.putCloseable(MDC_RUN_ID, runId);
             MDC.MDCCloseable payerId = MDC.putCloseable(MDC_PAYER, request.payerId())) {
            // One atomic setup snapshot; the setters inside are quiet so nothing is recorded twice.
            FaultSettings.Change setup;
            try {
                setup = payer.faults().change(() -> {
                    payer.faults().clear();
                    for (Fault fault : faults) {
                        if (fault == Fault.SLOW_RESPONSE) {
                            payer.faults().slowResponse(request.slowResponseDelayMs() == null
                                    ? properties.slowResponseDelay()
                                    : Duration.ofMillis(request.slowResponseDelayMs()));
                        } else {
                            payer.faults().enable(fault);
                        }
                    }
                });
            } catch (RuntimeException e) {
                auditSetupRejected(request.payerId(), payer.faults().snapshot());
                throw e;
            }
            auditFaults("fault.run_setup", request.payerId(), setup);
            try (HttpClient http = HttpClient.newBuilder()
                    .sslContext(payers.tls().clientContext())
                    .connectTimeout(Duration.ofSeconds(5))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build()) {
                return new Attempt(runId, request, sample, http, payers.credentials(), null, recordMetrics).run();
            }
        } finally {
            try {
                auditFaults("fault.run_reset", request.payerId(), payer.faults().change(payer.faults()::clear));
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * Refuses a {@code slowResponseDelayMs} outside 0 to {@link WorkbenchProperties#maxSlowResponseDelay()}. Above the
     * maximum, the workbench gives up on the hook call at {@code workbench.request-timeout} but the mock payer would
     * keep sleeping for the whole delay. A negative delay reaches the mock payer's fault setup, which refuses it only
     * after the payer lock and once a run id exists (#210), so both bounds are checked here, before any run starts.
     */
    private void checkSlowResponseDelay(RunRequest request) {
        Long delay = request.slowResponseDelayMs();
        long max = properties.maxSlowResponseDelay().toMillis();
        if (delay == null || (delay >= 0 && delay <= max)) { return; }
        AuditContext audit = AuditContext.current();
        if (audit != null) { audit.reasonCode = "invalid_slow_response_delay"; }
        throw new IllegalArgumentException(delay < 0
                ? "slowResponseDelayMs must be between 0 and " + max + " (workbench.request-timeout plus 1 s)"
                : "slowResponseDelayMs must be at most " + max + " (workbench.request-timeout plus 1 s)");
    }

    /** The payer was still held when the wait ended, or the wait was interrupted: no run is started. */
    private static PayerBusyException payerBusy(AuditContext audit, String payerId) {
        if (audit != null) { audit.reasonCode = "payer_busy"; }
        return new PayerBusyException(payerId);
    }

    /**
     * Runs the steps against a payer the user named. The destination is checked first and the
     * credential lives in a store made for this run alone, so it is gone when the run returns.
     *
     * @throws IllegalArgumentException if custom endpoints are off, or the endpoint, sample or
     *                                  credential is not acceptable
     * @throws RunsBusyException        if {@code workbench.max-concurrent-runs} custom runs are already in flight
     */
    private OnboardingRun runCustom(RunRequest request) {
        if (!properties.customEndpoints().enabled()) {
            throw new IllegalArgumentException("Custom endpoints are disabled. Set "
                    + "workbench.custom-endpoints.enabled=true to run against your own payer endpoint.");
        }
        SampleMetadata sample = samples.list().stream()
                .filter(s -> s.id().equals(request.sampleId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown sampleId: " + request.sampleId()));
        if (!request.faults().isEmpty()) {
            throw new IllegalArgumentException("Faults only apply to the synthetic payers");
        }
        EndpointGuard guard = new EndpointGuard();
        InMemoryCredentials credentials = new InMemoryCredentials();
        ConnectionRecord custom = customRecord(request, guard, credentials);
        checkSuffix(request, custom.baseUrl());
        AuditContext audit = AuditContext.current();
        if (!customRuns.tryAcquire()) {
            credentials.remove(CUSTOM_CREDENTIAL_REF);
            if (audit != null) { audit.reasonCode = "runs_busy"; }
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
            return new Attempt(runId, request, sample, guard.wrap(http), credentials, custom, true).run();
        } finally {
            credentials.remove(CUSTOM_CREDENTIAL_REF);
            customRuns.release();
        }
    }

    /** A setup that could not be applied changed nothing, so before and after are the same state. */
    private static void auditSetupRejected(String payerId, FaultSettings.Snapshot state) {
        AuditContext scope = AuditContext.current();
        if (scope != null) {
            scope.log.emit(scope, "fault.run_setup", "rejected", "payer", payerId, AuditEvent.Metadata.ofFaults(
                    null, "setup_failed", payerId, new FaultSettings.Change(state, state).audit()));
        }
    }

    private static void auditFaults(String action, String payerId, FaultSettings.Change change) {
        AuditContext scope = AuditContext.current();
        if (scope != null) {
            scope.log.emit(scope, action, "success", "payer", payerId,
                    AuditEvent.Metadata.ofFaults(null, null, payerId, change.audit()));
        }
    }

    private static java.net.URI approveDestination(EndpointGuard guard, String label, String url) {
        try { return guard.approve(label, url); }
        catch (IllegalArgumentException e) {
            AuditContext audit = AuditContext.current();
            if (audit != null) { audit.reasonCode = "destination_rejected"; }
            throw e;
        }
    }

    private static final String SUFFIX_RULE = "baseUrlSuffix may only add path segments to the base URL: "
            + "it must start with / and can't contain @, ?, #, \\, whitespace or control characters";

    /**
     * Refuses a {@code baseUrlSuffix} that would send the run anywhere but a path under the base URL,
     * before anything is sent or recorded. With no stored base URL only the suffix itself is checked;
     * the run then fails at resolve as before.
     */
    private static void checkSuffix(RunRequest request, String baseUrl) {
        String suffix = request.connection().baseUrlSuffix();
        if (!isSet(suffix)) { return; }
        try { withSuffix(baseUrl == null ? "https://localhost" : baseUrl, suffix); }
        catch (IllegalArgumentException e) {
            AuditContext audit = AuditContext.current();
            if (audit != null) { audit.reasonCode = "invalid_connection_edit"; }
            throw e;
        }
    }

    /**
     * {@code baseUrl} with {@code suffix} appended, as long as the result keeps the base URL's scheme,
     * host and port and gains no user info, query or fragment.
     *
     * @throws IllegalArgumentException otherwise
     */
    static String withSuffix(String baseUrl, String suffix) {
        String trimmed = suffix.trim();
        if (!trimmed.startsWith("/") || trimmed.chars().anyMatch(c -> c == '@' || c == '?' || c == '#' || c == '\\'
                || Character.isWhitespace(c) || Character.isISOControl(c))) {
            throw new IllegalArgumentException(SUFFIX_RULE);
        }
        String combined = baseUrl + trimmed;
        java.net.URI before;
        java.net.URI after;
        try {
            before = new java.net.URI(baseUrl);
            after = new java.net.URI(combined);
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException(SUFFIX_RULE);
        }
        if (after.getHost() == null || !after.getHost().equalsIgnoreCase(String.valueOf(before.getHost()))
                || !after.getScheme().equalsIgnoreCase(before.getScheme()) || after.getPort() != before.getPort()
                || after.getRawUserInfo() != null || after.getRawQuery() != null || after.getRawFragment() != null) {
            throw new IllegalArgumentException(SUFFIX_RULE);
        }
        return combined;
    }

    private static final String CUSTOM_CREDENTIAL_REF = "custom-endpoint-credential";

    private static ConnectionRecord customRecord(RunRequest request, EndpointGuard guard, InMemoryCredentials credentials) {
        RunRequest.CustomEndpoint endpoint = request.customEndpoint();
        AuthType auth = endpoint.authType() == null ? AuthType.NONE : endpoint.authType();
        if (auth != AuthType.NONE && auth != AuthType.OAUTH2_CLIENT_CREDENTIALS && auth != AuthType.CDS_HOOKS_JWT
                && auth != AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            throw new IllegalArgumentException("authType must be NONE, OAUTH2_CLIENT_CREDENTIALS, CDS_HOOKS_JWT or OAUTH2_PRIVATE_KEY_JWT");
        }
        String baseUrl = approveDestination(guard, "Base URL", endpoint.baseUrl()).toString();
        ConnectionRecord.Builder builder = ConnectionRecord.builder()
                .payerId(RunRequest.CUSTOM_PAYER_ID)
                .displayName("Custom endpoint")
                .environment(request.environment())
                .baseUrl(baseUrl)
                .authType(auth)
                .igVersion(isSet(endpoint.igVersion()) ? endpoint.igVersion().trim() : "2.0.1")
                .contactInfo("user-supplied endpoint");
        if (auth == AuthType.NONE) {
            if (isSet(endpoint.credential())) {
                throw new IllegalArgumentException("authType NONE takes no credential");
            }
            return builder.build();
        }
        if (!isSet(endpoint.clientId())) {
            throw new IllegalArgumentException("clientId is required for " + auth);
        }
        if (!isSet(endpoint.credential())) {
            throw new IllegalArgumentException("credential is required for " + auth);
        }
        builder.clientId(endpoint.clientId().trim());
        if (auth == AuthType.OAUTH2_CLIENT_CREDENTIALS || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            builder.tokenEndpoint(approveDestination(guard, "Token endpoint", endpoint.tokenEndpoint()).toString());
        }
        if (auth == AuthType.CDS_HOOKS_JWT || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            if (!isSet(endpoint.keyId())) {
                throw new IllegalArgumentException("keyId is required for " + auth);
            }
            builder.keyId(endpoint.keyId().trim());
        }
        credentials.put(CUSTOM_CREDENTIAL_REF, endpoint.credential());
        return builder.credentialRef(CUSTOM_CREDENTIAL_REF).build();
    }

    /** One run's state, passed from step to step. */
    private final class Attempt {
        private final String runId;
        private final RunRequest request;
        private final SampleMetadata sample;
        private final ExchangeRecorder recorder;
        private final List<StepResult> steps = new ArrayList<>();
        private final List<HookResponse> hookResponses = new ArrayList<>();
        private final InMemoryCredentials credentials;
        /** The user-supplied connection, or null when the run resolves a synthetic payer's stored one. */
        private final ConnectionRecord custom;
        private final boolean recordMetrics;
        private ConnectionRecord record;
        private HttpExchange discovery;
        private String serviceId;
        private Set<String> prefetchKeys = Set.of();
        private TokenResponseMetadata tokenResponse;
        private CdsHookResponse response;
        private RuntimeException callFailure;
        private final CdsHooksClient client;
        private Object jwtHeader;
        private Object jwtPayload;
        private JwtClaims clientJwt;
        private JwtClaims clientAssertion;
        /** The hook response's card count when it passed {@link #MAX_CARDS}; otherwise 0. */
        private int tooManyCards;

        Attempt(String runId, RunRequest request, SampleMetadata sample, HttpClient http,
                InMemoryCredentials credentials, ConnectionRecord custom, boolean recordMetrics) {
            this.recordMetrics = recordMetrics;
            this.recorder = new ExchangeRecorder(runId);
            this.credentials = credentials;
            this.custom = custom;
            HttpClient limited = new ResponseLimitClient(http, properties.maxResponseBytes(),
                    properties.maxResponseJsonValues(), properties.requestTimeout());
            this.client = new CdsHooksClient(new JwtObservingClient(new RequestIdClient(limited, runId),
                    this::observeAssertion, this::observeBearer),
                    credentials, null, properties.requestTimeout(), Duration.ofSeconds(5), recorder);
            this.runId = runId;
            this.request = request;
            this.sample = sample;
        }

        OnboardingRun run() {
            boolean ok = step(RESOLVE, this::resolve)
                    && step(DISCOVERY, this::discover)
                    && step(AUTHENTICATE, this::authenticate)
                    && step(HOOK_REQUEST, this::sendHook)
                    && step(PARSE_RESPONSE, this::parse);
            for (String id : ok ? List.<String>of() : STEP_ORDER.subList(steps.size(), STEP_ORDER.size())) {
                add(new StepResult(id, Instant.now(), Duration.ZERO, false,
                        "Skipped: an earlier step failed",
                        Map.of("status", "skipped")));
            }
            List<Finding> findings = new ArrayList<>();
            step(DIAGNOSTICS, details -> {
                findings.addAll(diagnose());
                details.put("counts", counts(findings));
                long fails = findings.stream().filter(f -> f.severity() == Severity.FAIL).count();
                return new Outcome(fails == 0, fails == 0
                        ? "No failures across " + findings.size() + " findings"
                        : fails + " failing check" + (fails == 1 ? "" : "s") + " out of " + findings.size() + " findings");
            });
            OnboardingRun run = new OnboardingRun(runId, request.payerId(), request.environment(), steps, findings);
            if (recordMetrics) {
                metrics.record(run, recorder.events());
            }
            return run;
        }

        // ---- steps ----

        private Outcome resolve(Map<String, Object> details) {
            Optional<ConnectionRecord> stored = custom != null ? Optional.of(custom) : payers.store()
                    .findByPayerIdAndEnvironment(request.payerId(), request.environment());
            if (stored.isEmpty()) {
                return Outcome.fail("No connection record for " + request.payerId() + " in "
                        + request.environment() + "; only SANDBOX is configured for the synthetic payers");
            }
            RunRequest.ConnectionOverrides edits = request.connection();
            Map<String, String> applied = new LinkedHashMap<>();
            ConnectionRecord.Builder builder = copy(stored.get());
            if (isSet(edits.baseUrlSuffix())) {
                String baseUrl = withSuffix(stored.get().baseUrl(), edits.baseUrlSuffix());
                builder.baseUrl(baseUrl);
                applied.put("baseUrl", baseUrl);
            }
            if (isSet(edits.igVersion())) {
                builder.igVersion(edits.igVersion().trim());
                applied.put("igVersion", edits.igVersion().trim());
            }
            if (isSet(edits.clientId())) {
                builder.clientId(edits.clientId().trim());
                applied.put("clientId", edits.clientId().trim());
            }
            record = builder.build();
            AuditContext audit = AuditContext.current();
            if (audit != null) {
                audit.authType = record.authType();
                audit.overrides = applied.keySet().stream().map(io.github.dflippojr.payerworkbench.core.AuditEvent.OverrideField::valueOf).toList();
            }
            details.put("connection", RedactedConnection.of(record));
            details.put("edited", applied);
            details.put("credential", record.authType() == AuthType.NONE ? "none (no authentication)"
                    : credentials.peek(record.credentialRef()).isPresent()
                    ? "present in the in-memory credential store (value never shown)" : "missing");
            return Outcome.pass("Resolved " + record.displayName() + " (" + record.environment() + ", "
                    + record.authType() + ")" + (applied.isEmpty() ? "" : "; edited: " + String.join(", ", applied.keySet())));
        }

        private Outcome discover(Map<String, Object> details) {
            List<CdsServiceDescriptor> services;
            try {
                // Both synthetic payers advertise public discovery. Preserve that
                // contract while sending the request through the same SDK client.
                services = client.discoverServices(copy(record).authType(AuthType.NONE).build());
            } catch (PayerCallException e) {
                return callFailed("Discovery", e);
            } catch (RouterException e) {
                // The payer answered, but the SDK could not read the body. Its message names neither the
                // entry nor the field, so say what the response shows instead.
                callFailure = e;
                services = null;
            } catch (IllegalArgumentException e) {
                // The SDK builds the URL before it sends anything, so no exchange exists to explain this.
                callFailure = e;
                return Outcome.fail("Discovery could not build its request URL: " + e.getMessage());
            } finally {
                List<PayerExchange> events = recorder.events(PayerCallPhase.DISCOVERY);
                if (!events.isEmpty()) {
                    discovery = ExchangeRecorder.adapt(events.getLast());
                }
                details.put("exchanges", exchangeViews(PayerCallPhase.DISCOVERY));
            }
            // The SDK maps a null entry to null rather than rejecting it.
            if (services == null || services.stream().anyMatch(Objects::isNull)) {
                return Outcome.fail(unreadableDiscovery());
            }
            List<Map<String, Object>> listed = new ArrayList<>();
            for (CdsServiceDescriptor service : services) {
                if (listed.size() < MAX_VIEWS) {
                    Map<String, Object> view = new LinkedHashMap<>();
                    view.put("id", TextLimit.cut(service.id()));
                    view.put("hook", TextLimit.cut(service.hook()));
                    List<String> keys = service.prefetch().keySet().stream().sorted().limit(MAX_LIST_ENTRIES)
                            .map(TextLimit::cut).toList();
                    view.put("prefetchKeys", keys);
                    putNotShown(view, "prefetchKeysNotShown", service.prefetch().size() - keys.size());
                    listed.add(view);
                }
                if (serviceId == null && sample.hook().equals(service.hook())) {
                    serviceId = service.id();
                    prefetchKeys = service.prefetch().keySet();
                }
            }
            details.put("services", listed);
            putNotShown(details, "servicesNotShown", services.size() - listed.size());
            if (serviceId == null) {
                return Outcome.fail("The payer advertises no " + sample.hook() + " service, which sample "
                        + sample.id() + " needs");
            }
            details.put("selectedService", TextLimit.cut(serviceId));
            if (!DiscoveryServicesCheck.isUrlSafeServiceId(serviceId)) {
                return Outcome.fail("The payer advertises service id '" + TextLimit.cut(serviceId) + "' for "
                        + sample.hook() + ", which cannot be used in a URL; it must be URL-safe");
            }
            if (serviceId.length() > TextLimit.MAX_CHARS) {
                return Outcome.fail("The payer advertises a service id of " + serviceId.length() + " characters for "
                        + sample.hook() + ", longer than the " + TextLimit.MAX_CHARS + " the workbench puts in a URL");
            }
            return Outcome.pass("Found " + services.size() + " services; " + sample.hook() + " is served by " + serviceId);
        }

        private String unreadableDiscovery() {
            JsonNode json = discovery == null ? null : readJson(discovery.responseBody());
            if (json == null) {
                return "The payer's discovery response is not JSON the client library can read";
            }
            for (JsonNode service : json.path("services")) {
                if (!service.isObject()) {
                    return UNREADABLE_SERVICES;
                }
            }
            return "The client library could not read the payer's discovery document: a service's hook, id, title "
                    + "or description is not a string, or its prefetch is not an object of query strings";
        }

        private Outcome authenticate(Map<String, Object> details) {
            details.put("authType", record.authType().name());
            invokeHook();
            if (record.authType() == AuthType.NONE) {
                // Nothing to obtain or sign. The hook-request step reports the payer's
                // answer, so a payer that does want credentials fails there.
                return Outcome.pass("No authentication configured; the hook call is sent without credentials");
            }
            if (record.authType() == AuthType.CDS_HOOKS_JWT) {
                details.put("jwtHeader", jwtHeader);
                details.put("jwtClaims", jwtPayload);
                details.put("requestUrl", serviceUrl());
                details.put("audMatchesRequestUrl", clientJwt != null && clientJwt.aud().contains(serviceUrl()));
                return clientJwt == null ? Outcome.fail("The SDK could not sign the client JWT")
                        : Outcome.pass("Signed a CDS Hooks client JWT as " + record.clientId() + " (kid " + record.keyId()
                                + ") for aud " + serviceUrl());
            }
            if (clientAssertion != null) {
                details.put("clientAssertionClaims", clientAssertion);
            }
            return clientCredentials(details);
        }

        private void invokeHook() {
            PrefetchVariant variant = prefetchKeys.contains("coverageBundle") ? PrefetchVariant.PAYER_B : PrefetchVariant.STANDARD;
            Sample loaded = samples.load(sample.id(), variant).withNewHookInstance();
            // Authentication is lazy in the SDK. Invoke once and project its
            // TOKEN and HOOK events into their separate timeline steps below.
            try {
                response = client.callHook(record, serviceId, loaded.request());
            } catch (RuntimeException e) {
                // IllegalArgumentException: the SDK could not build the request URL, so nothing was sent.
                // Anything else may come from reading an answered response, such as the NullPointerException
                // a null card raises (#208); the recorded exchange below still goes to the later steps.
                callFailure = e;
            }
            List<PayerExchange> hooks = recorder.events(PayerCallPhase.HOOK);
            if (!hooks.isEmpty()) {
                hookResponses.add(new HookResponse(serviceId, sample.hook(), sample.id(),
                        ExchangeRecorder.adapt(hooks.getLast()), clientJwt));
            }
        }

        private Outcome clientCredentials(Map<String, Object> details) {
            List<PayerExchange> tokens = recorder.events(PayerCallPhase.TOKEN);
            details.put("exchanges", exchangeViews(PayerCallPhase.TOKEN));
            if (tokens.isEmpty()) {
                return Outcome.fail("The SDK could not authenticate: " + failureMessage());
            }
            PayerExchange last = tokens.getLast();
            // The listener intentionally omits access_token. A HOOK event proves
            // the SDK accepted the token, without exposing its value here.
            boolean accepted = !hookResponses.isEmpty();
            tokenResponse = tokenMetadata(last, accepted);
            details.put("token", Map.of("accessTokenPresent", accepted,
                    "tokenType", String.valueOf(tokenResponse.tokenType()),
                    "expiresInSeconds", String.valueOf(tokenResponse.expiresInSeconds())));
            if (callFailure instanceof PayerCallException e && e.phase() == PayerCallPhase.TOKEN) {
                return callFailed("Token request", e);
            }
            return accepted ? Outcome.pass("Got " + tokenKind(tokenResponse.tokenType()) + " for client "
                    + record.clientId() + " (" + (tokenResponse.expiresInSeconds() == null ? "no usable expires_in"
                            : "expires in " + tokenResponse.expiresInSeconds() + " s") + "; value hidden)")
                    : Outcome.fail("The SDK could not authenticate: " + failureMessage());
        }

        /** The token as the Authenticate summary names it: its type, or that the response named none (#218). */
        private static String tokenKind(String tokenType) {
            return tokenType == null || tokenType.isBlank() ? "an access token with no token_type"
                    : "a " + tokenType + " access token";
        }

        private TokenResponseMetadata tokenMetadata(PayerExchange event, boolean accepted) {
            JsonNode json = Optional.ofNullable(readJson(event.responseBody())).orElseGet(mapper::createObjectNode);
            JsonNode error = callFailure instanceof PayerCallException e && e.phase() == PayerCallPhase.TOKEN
                    ? readJson(e.responseBody()) : null;
            String scope = text(json, "scope");
            List<String> scopes = new ArrayList<>();
            int notShown = 0;
            // Walk the scope instead of splitting it: a 4 MiB "a a a ..." would make two million strings.
            for (int start = 0; scope != null && start < scope.length(); ) {
                int end = scope.indexOf(' ', start);
                end = end < 0 ? scope.length() : end;
                if (end > start && scopes.size() < TokenResponseMetadata.MAX_SCOPES) {
                    scopes.add(TextLimit.cut(scope.substring(start, Math.min(end, start + TextLimit.MAX_CHARS + 1))));
                } else if (end > start) {
                    notShown++;
                }
                start = end + 1;
            }
            JsonNode expiresIn = json.hasNonNull("expires_in") ? json.get("expires_in") : null;
            return new TokenResponseMetadata(accepted, text(json, "token_type"), ExpiresIn.seconds(expiresIn),
                    expiresIn == null ? null : expiresIn.toString(),
                    scopes, notShown, text(error, "error"), text(error, "error_description"));
        }

        /** Only the token request's client_assertion is the SMART client's own JWT. */
        private void observeAssertion(String jwt) {
            String[] parts = jwt.split("\\.");
            if (record != null && parts.length == 3 && record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
                clientAssertion = claimsOf(parts[0], parts[1]);
            }
        }

        /** For SMART the Bearer value is the payer's access token, so only CDS Hooks JWT reads it. */
        private void observeBearer(String jwt) {
            String[] parts = jwt.split("\\.");
            if (record != null && parts.length == 3 && record.authType() == AuthType.CDS_HOOKS_JWT) {
                jwtHeader = decode(parts[0]);
                jwtPayload = decode(parts[1]);
                clientJwt = claimsOf(parts[0], parts[1]);
            }
        }

        private Outcome sendHook(Map<String, Object> details) {
            details.put("sample", sample.id());
            details.put("prefetchVariant", prefetchKeys.contains("coverageBundle") ? "PAYER_B" : "STANDARD");
            details.put("exchanges", exchangeViews(PayerCallPhase.HOOK));
            if (callFailure instanceof PayerCallException e) {
                return callFailed("Hook call to " + serviceId, e);
            }
            if (hookResponses.isEmpty()) {
                return Outcome.fail(failureMessage());
            }
            HttpExchange exchange = hookResponses.getLast().exchange();
            return Outcome.pass("HTTP " + exchange.status() + " from " + serviceId + " in "
                    + exchange.latency().toMillis() + " ms");
        }

        /** Names a {@code field} that is not a list of objects, such as "card 1 is not a JSON object". */
        private static String listProblem(JsonNode json, String field, String name) {
            JsonNode list = json.path(field);
            if (!list.isArray()) {
                return list.isMissingNode() || list.isNull() ? null : field + " is not an array";
            }
            for (int i = 0; i < list.size(); i++) {
                if (!list.get(i).isObject()) {
                    return name + " " + (i + 1) + " is not a JSON object";
                }
            }
            return null;
        }

        private String failureMessage() {
            if (callFailure == null) {
                return "No HTTP exchange observed";
            }
            return callFailure.getMessage() == null ? callFailure.getClass().getSimpleName() : callFailure.getMessage();
        }

        private List<ExchangeView> exchangeViews(PayerCallPhase phase) {
            return recorder.events(phase).stream().map(ExchangeRecorder::adapt).map(ExchangeView::of).toList();
        }

        private Outcome callFailed(String what, PayerCallException failure) {
            ResponseTooLargeException tooLarge = ResponseTooLargeException.in(failure);
            if (tooLarge != null && tooLarge.measure() == ResponseTooLargeException.Measure.JSON_VALUES) {
                return Outcome.fail(what + " got HTTP " + tooLarge.statusCode() + ", but the response holds more than "
                        + tooLarge.describeLimit() + ", so the workbench did not parse it");
            }
            if (tooLarge != null) {
                return Outcome.fail(what + " got HTTP " + tooLarge.statusCode() + ", but the response exceeded the "
                        + tooLarge.describeLimit() + " limit, so the workbench stopped reading it");
            }
            return Outcome.fail(failure.statusCode().isPresent()
                    ? what + " returned HTTP " + failure.statusCode().getAsInt()
                    : what + " got no response: " + failure.getMessage());
        }

        private Outcome parse(Map<String, Object> details) {
            HttpExchange exchange = hookResponses.getLast().exchange();
            JsonNode json = readJson(exchange.responseBody());
            if (json == null || !json.isObject()) {
                return Outcome.fail("The hook response is not a JSON object");
            }
            if (!json.path("cards").isArray()) {
                return Outcome.fail("The hook response has no cards array");
            }
            String problem = Optional.ofNullable(listProblem(json, "cards", "card"))
                    .orElseGet(() -> listProblem(json, "systemActions", "system action"));
            if (problem != null) {
                return Outcome.fail("The hook response's " + problem);
            }
            if (response == null) {
                return Outcome.fail("The client library could not read the response: " + failureMessage());
            }
            List<Card> cards = response.cards();
            List<SystemAction> actions = response.systemActions();
            List<CoverageInformation> coverageInformation = response.coverageInformation();
            // The SDK's parsed response is the largest thing a run holds, and no later step reads it.
            response = null;
            if (cards.size() > MAX_CARDS) {
                tooManyCards = cards.size();
                details.put("cardCount", cards.size());
                return Outcome.fail("The hook response has " + cards.size() + " cards, more than the "
                        + MAX_CARDS + " the workbench reads one by one");
            }
            List<Map<String, Object>> cardViews = new ArrayList<>();
            List<String> problems = new ArrayList<>();
            int lacking = 0;
            for (int i = 0; i < cards.size(); i++) {
                Card card = cards.get(i);
                if (i < MAX_VIEWS) {
                    Map<String, Object> view = new LinkedHashMap<>();
                    view.put("summary", TextLimit.cut(card.summary()));
                    view.put("indicator", TextLimit.cut(card.indicator()));
                    view.put("source", card.source() == null ? null : TextLimit.cut(card.source().label()));
                    cardViews.add(view);
                }
                if ((card.summary() == null || card.indicator() == null || card.source() == null
                        || card.source().label() == null) && lacking++ < MAX_PROBLEMS) {
                    problems.add("card " + (i + 1) + " lacks " + missingCardFields(card));
                }
            }
            if (lacking > problems.size()) {
                problems.add("and " + (lacking - problems.size()) + " more cards lack fields");
            }
            List<Map<String, Object>> coverage = new ArrayList<>();
            for (CoverageInformation info : coverageInformation.subList(0, Math.min(MAX_VIEWS, coverageInformation.size()))) {
                Map<String, Object> view = new LinkedHashMap<>();
                view.put("resource", TextLimit.cut(info.resourceReference()));
                view.put("covered", TextLimit.cut(info.covered()));
                view.put("paNeeded", TextLimit.cut(info.paNeeded()));
                List<String> docNeeded = info.docNeeded() == null ? null : info.docNeeded().stream()
                        .limit(MAX_LIST_ENTRIES).map(TextLimit::cut).toList();
                view.put("docNeeded", docNeeded);
                if (docNeeded != null) {
                    putNotShown(view, "docNeededNotShown", info.docNeeded().size() - docNeeded.size());
                }
                coverage.add(view);
            }
            details.put("cards", cardViews);
            putNotShown(details, "cardsNotShown", cards.size() - cardViews.size());
            details.put("systemActions", actions.size());
            details.put("coverageInformation", coverage);
            putNotShown(details, "coverageInformationNotShown", coverageInformation.size() - coverage.size());
            if (!problems.isEmpty()) {
                return Outcome.fail("Parsed " + cards.size() + " cards, but " + String.join("; ", problems));
            }
            return Outcome.pass("Parsed " + cards.size() + " cards, " + actions.size() + " system actions and "
                    + coverageInformation.size() + " coverage-information entries");
        }

        private List<Finding> diagnose() {
            RunObservations.Builder obs = RunObservations.builder(record != null
                    ? RedactedConnection.of(record)
                    : new RedactedConnection(request.payerId(), null, request.environment(), null, null, null, null,
                            null, null, null, List.of(), false, false, null, null));
            // Retry attempts remain visible in the timeline. Diagnose the final
            // hook outcome once so a recovered 401 cannot produce a false FAIL.
            recorder.events(PayerCallPhase.DISCOVERY).stream().map(ExchangeRecorder::adapt).forEach(obs::exchange);
            recorder.events(PayerCallPhase.TOKEN).stream().map(ExchangeRecorder::adapt).forEach(obs::exchange);
            hookResponses.forEach(h -> obs.exchange(h.exchange()));
            obs.discovery(discovery).tokenResponse(tokenResponse).clientAssertion(clientAssertion);
            hookResponses.forEach(obs::hookResponse);
            DiagnosticsConfig defaults = DiagnosticsConfig.defaults();
            DiagnosticsConfig config = new DiagnosticsConfig(Set.of(sample.hook()), properties.latencyWarn(),
                    properties.latencyFail(), defaults.clockSkewTolerance());
            List<Finding> findings = new ArrayList<>(new DiagnosticEngine(config).run(obs.build()));
            findings.addAll(workbenchFindings());
            if (findings.stream().noneMatch(f -> f.severity() == Severity.FAIL)) {
                brokenStepFinding().ifPresent(findings::add);
            }
            findings.sort(Comparator.comparing(Finding::severity).reversed());
            return findings;
        }

        /**
         * What the engine can't see: a run that never found a connection record, so
         * nothing was sent.
         */
        private List<Finding> workbenchFindings() {
            List<Finding> findings = new ArrayList<>();
            if (record == null) {
                findings.add(new Finding(CONNECTION_RECORD_CHECK, Severity.FAIL, "No connection record for this environment",
                        "The directory has no ConnectionRecord for " + request.payerId() + " in "
                                + request.environment() + ", so the router would not know where to send hook "
                                + "calls or how to authenticate. Nothing was sent to the payer.",
                        "payerId: " + request.payerId() + "\nenvironment: " + request.environment(),
                        "Add a ConnectionRecord for this payer and environment (base URL, auth type, client id "
                                + "and a credential reference), or pick an environment that has one."));
            }
            recorder.events().stream()
                    .filter(e -> ResponseTooLargeException.in(e.error()) != null)
                    .findFirst()
                    .ifPresent(e -> findings.add(responseTooLarge(e, ResponseTooLargeException.in(e.error()))));
            if (tooManyCards > 0) {
                findings.add(new Finding(TOO_MANY_CARDS_CHECK, Severity.FAIL, "Hook response holds " + tooManyCards + " cards",
                        "The payer answered the hook call with " + tooManyCards + " cards. A CDS Hooks response "
                                + "carries a few cards for the clinician to read, so past " + MAX_CARDS + " the "
                                + "workbench stops instead of reading each card.",
                        "service: " + serviceId + "\ncards: " + tooManyCards + "\nlimit: " + MAX_CARDS,
                        "Ask the payer to return only the cards that matter for this order, or to merge "
                                + "repeated cards into one."));
            }
            return findings;
        }

        private Finding responseTooLarge(PayerExchange exchange, ResponseTooLargeException tooLarge) {
            String limit = tooLarge.describeLimit();
            String call = exchange.phase().name().toLowerCase(Locale.ROOT);
            if (tooLarge.measure() == ResponseTooLargeException.Measure.JSON_VALUES) {
                return new Finding(RESPONSE_TOO_LARGE_CHECK, Severity.FAIL, "Response holds more than " + limit,
                        "The payer answered the " + call + " call with a body of more than " + limit + " ("
                                + tooLarge.setting() + "), so the workbench did not parse it. Building that many "
                                + "objects can exhaust a client's memory even when the body is small in bytes, "
                                + "as with a long array of empty cards.",
                        exchange.method() + " " + exchange.uri() + "\nstatus: " + tooLarge.statusCode()
                                + "\nbytes: " + tooLarge.bytesRead() + "\nlimit: " + limit,
                        "Return fewer entries: drop repeated cards, actions or services. If the size is expected, "
                                + "start the workbench with a larger " + tooLarge.setting() + ".");
            }
            return new Finding(RESPONSE_TOO_LARGE_CHECK, Severity.FAIL, "Response larger than the " + limit + " limit",
                    "The payer answered the " + call
                            + " call, but its body ran past " + limit + " (workbench.max-response-bytes), so the "
                            + "workbench stopped reading it and kept only the first " + limit + ". A CDS Hooks "
                            + "client would also have to read and parse the whole body before it could show a card.",
                    exchange.method() + " " + exchange.uri() + "\nstatus: " + tooLarge.statusCode()
                            + "\nbytes received before stopping: " + tooLarge.bytesRead()
                            + "\nlimit: " + tooLarge.limit() + " bytes",
                    "Return a smaller response: drop padding, debug output or large embedded resources. If the "
                            + "size is expected, start the workbench with a larger workbench.max-response-bytes.");
        }

        /**
         * A step that failed without leaving evidence any check could read, such as a request the SDK
         * could not build. Without this the report would say FAIL with an empty Findings section.
         */
        private Optional<Finding> brokenStepFinding() {
            return steps.stream().filter(s -> !s.ok() && !DIAGNOSTICS.equals(s.stepId())).findFirst().map(step ->
                    answered(step)
                            ? new Finding(STEP_FAILED_CHECK, Severity.FAIL,
                                    RunVerdict.title(step.stepId()) + " failed after the payer answered",
                                    "The payer answered this step, but the run stopped here and no check that reads "
                                            + "payer responses named the cause.",
                                    "step: " + RunVerdict.title(step.stepId()) + "\nsummary: " + step.summary(),
                                    "Fix what the summary names and run again. The step's details show the "
                                            + "payer's response.")
                            : new Finding(STEP_FAILED_CHECK, Severity.FAIL,
                                    RunVerdict.title(step.stepId()) + " failed with no payer response to diagnose",
                                    "The run stopped at this step before the payer answered, so none of the checks "
                                            + "that read payer responses had anything to say.",
                                    "step: " + RunVerdict.title(step.stepId()) + "\nsummary: " + step.summary(),
                                    "Fix what the summary names and run again. The step's details show what was "
                                            + "attempted."));
        }

        /** Whether the step recorded an HTTP response from the payer. */
        private static boolean answered(StepResult step) {
            return step.details().get("exchanges") instanceof List<?> exchanges && exchanges.stream()
                    .anyMatch(e -> e instanceof ExchangeView view && view.status() != HttpExchange.NO_RESPONSE);
        }

        // ---- helpers ----

        private boolean step(String id, StepBody body) {
            Instant startedAt = Instant.now();
            long start = System.nanoTime();
            Map<String, Object> details = new LinkedHashMap<>();
            Outcome outcome;
            try {
                outcome = body.run(details);
            } catch (RuntimeException e) {
                outcome = Outcome.fail("Unexpected error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
            PayerCallPhase phase = switch (id) {
                case AUTHENTICATE -> PayerCallPhase.TOKEN;
                case HOOK_REQUEST -> PayerCallPhase.HOOK;
                default -> null;
            };
            if (phase != null) {
                List<PayerExchange> events = recorder.events(phase);
                elapsed = events.stream().map(PayerExchange::elapsed).reduce(Duration.ZERO, Duration::plus);
                if (!events.isEmpty()) {
                    startedAt = events.getFirst().startedAt();
                }
            }
            details.put("status", outcome.ok() ? "passed" : "failed");
            add(new StepResult(id, startedAt, elapsed, outcome.ok(), outcome.summary(), details));
            return outcome.ok();
        }

        /** Keeps a step and logs its one structured line; the summary and details stay out of the log. */
        private void add(StepResult step) {
            steps.add(step);
            LOG.info("step runId={} payer={} step={} status={} ms={}", runId, request.payerId(), step.stepId(),
                    step.details().get("status"), step.elapsed().toMillis());
        }

        private String serviceUrl() {
            String base = record.baseUrl();
            return (base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + "/cds-services/" + serviceId;
        }
    }

    @FunctionalInterface
    private interface StepBody {
        Outcome run(Map<String, Object> details);
    }

    private record Outcome(boolean ok, String summary) {
        static Outcome pass(String summary) {
            return new Outcome(true, summary);
        }

        static Outcome fail(String summary) {
            return new Outcome(false, summary);
        }
    }

    /** Records how many entries of a list were left out of a step's details, when any were. */
    private static void putNotShown(Map<String, Object> details, String key, int count) {
        if (count > 0) {
            details.put(key, count);
        }
    }

    private static Map<Severity, Long> counts(List<Finding> findings) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, findings.stream().filter(f -> f.severity() == severity).count());
        }
        return counts;
    }

    private static String missingCardFields(Card card) {
        List<String> missing = new ArrayList<>();
        if (card.summary() == null) {
            missing.add("summary");
        }
        if (card.indicator() == null) {
            missing.add("indicator");
        }
        if (card.source() == null || card.source().label() == null) {
            missing.add("source.label");
        }
        return String.join(", ", missing);
    }

    private JsonNode readJson(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            return mapper.readTree(body);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /**
     * The non-secret claims of a compact JWT, from its encoded header and payload.
     * The token and its signature are never kept.
     */
    private JwtClaims claimsOf(String header, String payload) {
        try {
            JsonNode h = mapper.readTree(Base64.getUrlDecoder().decode(header));
            JsonNode p = mapper.readTree(Base64.getUrlDecoder().decode(payload));
            List<String> aud = new ArrayList<>();
            if (p.path("aud").isArray()) {
                p.get("aud").forEach(a -> aud.add(a.asText()));
            } else if (p.hasNonNull("aud")) {
                aud.add(p.get("aud").asText());
            }
            return new JwtClaims(text(p, "iss"), aud, epochSeconds(p, "exp"), epochSeconds(p, "iat"), text(p, "jti"),
                    text(h, "kid"), text(p, "sub"));
        } catch (java.io.IOException | IllegalArgumentException e) {
            return null;
        }
    }

    static Instant epochSeconds(JsonNode json, String field) {
        return json.path(field).isNumber() ? Instant.ofEpochSecond(json.get(field).asLong()) : null;
    }

    private Object decode(String base64url) {
        try {
            return mapper.convertValue(mapper.readTree(Base64.getUrlDecoder().decode(base64url)), Map.class);
        } catch (java.io.IOException | IllegalArgumentException e) {
            return null;
        }
    }

    private static String text(JsonNode json, String field) {
        return json != null && json.hasNonNull(field) ? json.get(field).asText() : null;
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private static ConnectionRecord.Builder copy(ConnectionRecord r) {
        return ConnectionRecord.builder()
                .payerId(r.payerId())
                .displayName(r.displayName())
                .environment(r.environment())
                .baseUrl(r.baseUrl())
                .authType(r.authType())
                .tokenEndpoint(r.tokenEndpoint())
                .clientId(r.clientId())
                .keyId(r.keyId())
                .jwksUrl(r.jwksUrl())
                .tenant(r.tenant())
                .mtlsCredentialRef(r.mtlsCredentialRef())
                .scopes(r.scopes())
                .credentialRef(r.credentialRef())
                .igVersion(r.igVersion())
                .status(r.status())
                .lastVerifiedAt(r.lastVerifiedAt())
                .contactInfo(r.contactInfo())
                .createdAt(r.createdAt())
                .updatedAt(r.updatedAt());
    }
}
