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
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.payerworkbench.core.Finding;
import io.github.dflippojr.payerworkbench.core.HookResponse;
import io.github.dflippojr.payerworkbench.core.HttpExchange;
import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.OnboardingRun;
import io.github.dflippojr.payerworkbench.core.RedactedConnection;
import io.github.dflippojr.payerworkbench.core.RunObservations;
import io.github.dflippojr.payerworkbench.core.Severity;
import io.github.dflippojr.payerworkbench.core.StepResult;
import io.github.dflippojr.payerworkbench.core.TokenResponseMetadata;
import io.github.dflippojr.payerworkbench.diagnostics.DiagnosticEngine;
import io.github.dflippojr.payerworkbench.diagnostics.DiagnosticsConfig;
import io.github.dflippojr.payerworkbench.mock.Fault;
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
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
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
 * the same payer are serialized so one run's faults never leak into another's.
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

    public OnboardingRunner(SyntheticPayers payers, SampleCatalog samples, WorkbenchProperties properties,
                            RunMetrics metrics) {
        this.payers = payers;
        this.samples = samples;
        this.properties = properties;
        this.metrics = metrics;
    }

    /**
     * Runs the steps for {@code request}.
     *
     * @throws IllegalArgumentException if the payer, sample or a fault id is unknown
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

    private OnboardingRun run(RunRequest request, boolean recordMetrics) {
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

        String runId = UUID.randomUUID().toString();
        ReentrantLock lock = locks.computeIfAbsent(request.payerId(), id -> new ReentrantLock());
        lock.lock();
        try (MDC.MDCCloseable id = MDC.putCloseable(MDC_RUN_ID, runId);
             MDC.MDCCloseable payerId = MDC.putCloseable(MDC_PAYER, request.payerId())) {
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
            try (HttpClient http = HttpClient.newBuilder()
                    .sslContext(payers.tls().clientContext())
                    .connectTimeout(Duration.ofSeconds(5))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build()) {
                return new Attempt(runId, request, sample, http, payers.credentials(), null, recordMetrics).run();
            }
        } finally {
            payer.faults().clear();
            lock.unlock();
        }
    }

    /**
     * Runs the steps against a payer the user named. The destination is checked first and the
     * credential lives in a store made for this run alone, so it is gone when the run returns.
     *
     * @throws IllegalArgumentException if custom endpoints are off, or the endpoint, sample or
     *                                  credential is not acceptable
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

        String runId = UUID.randomUUID().toString();
        try (MDC.MDCCloseable id = MDC.putCloseable(MDC_RUN_ID, runId);
             MDC.MDCCloseable payerId = MDC.putCloseable(MDC_PAYER, request.payerId());
             HttpClient http = HttpClient.newBuilder()
                     .connectTimeout(Duration.ofSeconds(5))
                     .followRedirects(HttpClient.Redirect.NEVER)
                     .build()) {
            return new Attempt(runId, request, sample, guard.wrap(http), credentials, custom, true).run();
        } finally {
            credentials.remove(CUSTOM_CREDENTIAL_REF);
        }
    }

    private static final String CUSTOM_CREDENTIAL_REF = "custom-endpoint-credential";

    private static ConnectionRecord customRecord(RunRequest request, EndpointGuard guard, InMemoryCredentials credentials) {
        RunRequest.CustomEndpoint endpoint = request.customEndpoint();
        AuthType auth = endpoint.authType() == null ? AuthType.NONE : endpoint.authType();
        if (auth != AuthType.NONE && auth != AuthType.OAUTH2_CLIENT_CREDENTIALS && auth != AuthType.CDS_HOOKS_JWT
                && auth != AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            throw new IllegalArgumentException("authType must be NONE, OAUTH2_CLIENT_CREDENTIALS, CDS_HOOKS_JWT or OAUTH2_PRIVATE_KEY_JWT");
        }
        String baseUrl = guard.approve("Base URL", endpoint.baseUrl()).toString();
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
            builder.tokenEndpoint(guard.approve("Token endpoint", endpoint.tokenEndpoint()).toString());
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

        Attempt(String runId, RunRequest request, SampleMetadata sample, HttpClient http,
                InMemoryCredentials credentials, ConnectionRecord custom, boolean recordMetrics) {
            this.recordMetrics = recordMetrics;
            this.recorder = new ExchangeRecorder(runId);
            this.credentials = credentials;
            this.custom = custom;
            this.client = new CdsHooksClient(new JwtObservingClient(new RequestIdClient(http, runId), this::observeJwt),
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
                String baseUrl = stored.get().baseUrl() + edits.baseUrlSuffix().trim();
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
            details.put("connection", RedactedConnection.of(record));
            details.put("edited", applied);
            details.put("credential", record.authType() == AuthType.NONE ? "none (no authentication)"
                    : credentials.resolve(record.credentialRef()).isPresent()
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
            } finally {
                List<PayerExchange> events = recorder.events(PayerCallPhase.DISCOVERY);
                if (!events.isEmpty()) {
                    discovery = ExchangeRecorder.adapt(events.getLast());
                }
                details.put("exchanges", exchangeViews(PayerCallPhase.DISCOVERY));
            }
            List<Map<String, Object>> listed = new ArrayList<>();
            for (CdsServiceDescriptor service : services) {
                Map<String, Object> view = new LinkedHashMap<>();
                view.put("id", service.id());
                view.put("hook", service.hook());
                view.put("prefetchKeys", service.prefetch().keySet().stream().sorted().toList());
                listed.add(view);
                if (serviceId == null && sample.hook().equals(service.hook())) {
                    serviceId = service.id();
                    prefetchKeys = service.prefetch().keySet();
                }
            }
            details.put("services", listed);
            if (serviceId == null) {
                return Outcome.fail("The payer advertises no " + sample.hook() + " service, which sample "
                        + sample.id() + " needs");
            }
            details.put("selectedService", serviceId);
            return Outcome.pass("Found " + listed.size() + " services; " + sample.hook() + " is served by " + serviceId);
        }

        private Outcome authenticate(Map<String, Object> details) {
            details.put("authType", record.authType().name());
            invokeHook();
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
            } catch (RouterException e) {
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
            return accepted ? Outcome.pass("Got a " + tokenResponse.tokenType() + " access token for client "
                    + record.clientId() + " (expires in " + tokenResponse.expiresInSeconds() + " s; value hidden)")
                    : Outcome.fail("The SDK could not authenticate: " + failureMessage());
        }

        private TokenResponseMetadata tokenMetadata(PayerExchange event, boolean accepted) {
            JsonNode json = Optional.ofNullable(readJson(event.responseBody())).orElseGet(mapper::createObjectNode);
            JsonNode error = callFailure instanceof PayerCallException e && e.phase() == PayerCallPhase.TOKEN
                    ? readJson(e.responseBody()) : null;
            return new TokenResponseMetadata(accepted, text(json, "token_type"),
                    json.hasNonNull("expires_in") ? json.get("expires_in").asLong() : null,
                    json.hasNonNull("scope") ? List.of(json.get("scope").asText().split(" ")) : List.of(),
                    text(error, "error"), text(error, "error_description"));
        }

        private void observeJwt(String jwt) {
            if (record == null) {
                return;
            }
            String[] parts = jwt.split("\\.");
            if (parts.length == 3 && record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
                clientAssertion = claimsOf(parts[0], parts[1]);
            } else if (parts.length == 3 && record.authType() == AuthType.CDS_HOOKS_JWT) {
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

        private String failureMessage() {
            return callFailure == null ? "No HTTP exchange observed" : callFailure.getMessage();
        }

        private List<ExchangeView> exchangeViews(PayerCallPhase phase) {
            return recorder.events(phase).stream().map(ExchangeRecorder::adapt).map(ExchangeView::of).toList();
        }

        private Outcome callFailed(String what, PayerCallException failure) {
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
            if (response == null) {
                return Outcome.fail("The client library could not read the response: " + failureMessage());
            }
            List<Card> cards = response.cards();
            List<SystemAction> actions = response.systemActions();
            List<Map<String, Object>> cardViews = new ArrayList<>();
            List<String> problems = new ArrayList<>();
            for (int i = 0; i < cards.size(); i++) {
                Card card = cards.get(i);
                Map<String, Object> view = new LinkedHashMap<>();
                view.put("summary", card.summary());
                view.put("indicator", card.indicator());
                view.put("source", card.source() == null ? null : card.source().label());
                cardViews.add(view);
                if (card.summary() == null || card.indicator() == null || card.source() == null
                        || card.source().label() == null) {
                    problems.add("card " + (i + 1) + " lacks " + missingCardFields(card));
                }
            }
            List<Map<String, Object>> coverage = new ArrayList<>();
            for (CoverageInformation info : response.coverageInformation()) {
                Map<String, Object> view = new LinkedHashMap<>();
                view.put("resource", info.resourceReference());
                view.put("covered", info.covered());
                view.put("paNeeded", info.paNeeded());
                view.put("docNeeded", info.docNeeded());
                coverage.add(view);
            }
            details.put("cards", cardViews);
            details.put("systemActions", actions.size());
            details.put("coverageInformation", coverage);
            if (!problems.isEmpty()) {
                return Outcome.fail("Parsed " + cards.size() + " cards, but " + String.join("; ", problems));
            }
            return Outcome.pass("Parsed " + cards.size() + " cards, " + actions.size() + " system actions and "
                    + coverage.size() + " coverage-information entries");
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
            return findings;
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

    private static Instant epochSeconds(JsonNode json, String field) {
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
