package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.Card;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.SystemAction;
import io.github.dflippojr.fhircrdrouter.client.auth.JwtSigner;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
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
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
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

    private final SyntheticPayers payers;
    private final SampleCatalog samples;
    private final WorkbenchProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public OnboardingRunner(SyntheticPayers payers, SampleCatalog samples, WorkbenchProperties properties) {
        this.payers = payers;
        this.samples = samples;
        this.properties = properties;
    }

    /**
     * Runs the steps for {@code request}.
     *
     * @throws IllegalArgumentException if the payer, sample or a fault id is unknown
     */
    public OnboardingRun run(RunRequest request) {
        MockPayer payer = payers.payer(request.payerId())
                .orElseThrow(() -> new IllegalArgumentException("Unknown payerId: " + request.payerId()));
        SampleMetadata sample = samples.list().stream()
                .filter(s -> s.id().equals(request.sampleId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown sampleId: " + request.sampleId()));
        List<Fault> faults = request.faults().stream()
                .map(id -> Fault.fromId(id).orElseThrow(() -> new IllegalArgumentException("Unknown fault: " + id)))
                .toList();

        ReentrantLock lock = locks.computeIfAbsent(request.payerId(), id -> new ReentrantLock());
        lock.lock();
        try {
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
                return new Attempt(request, sample, http).run();
            }
        } finally {
            payer.faults().clear();
            lock.unlock();
        }
    }

    /** One run's state, passed from step to step. */
    private final class Attempt {
        private final RunRequest request;
        private final SampleMetadata sample;
        private final ExchangeRecorder recorder;
        private final List<StepResult> steps = new ArrayList<>();
        private final List<HookResponse> hookResponses = new ArrayList<>();
        private ConnectionRecord record;
        private HttpExchange discovery;
        private String serviceId;
        private Set<String> prefetchKeys = Set.of();
        private TokenResponseMetadata tokenResponse;
        private String authorization;
        private String hookBody;
        private JwtClaims clientJwt;

        Attempt(RunRequest request, SampleMetadata sample, HttpClient http) {
            this.recorder = new ExchangeRecorder(http, properties.requestTimeout());
            this.request = request;
            this.sample = sample;
        }

        OnboardingRun run() {
            boolean ok = step(RESOLVE, this::resolve)
                    && step(DISCOVERY, this::discover)
                    && step(AUTHENTICATE, this::authenticate)
                    && step(HOOK_REQUEST, this::sendHook)
                    && step(PARSE_RESPONSE, this::parse);
            for (String id : STEP_ORDER.subList(steps.size(), STEP_ORDER.size())) {
                steps.add(new StepResult(id, Instant.now(), Duration.ZERO, false,
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
            return new OnboardingRun(UUID.randomUUID().toString(), request.payerId(), request.environment(),
                    steps, findings);
        }

        // ---- steps ----

        private Outcome resolve(Map<String, Object> details) {
            Optional<ConnectionRecord> stored = payers.store()
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
            if (isSet(edits.audOverride())) {
                applied.put("aud", edits.audOverride().trim());
            }
            record = builder.build();
            details.put("connection", RedactedConnection.of(record));
            details.put("edited", applied);
            details.put("credential", payers.credentials().resolve(record.credentialRef()).isPresent()
                    ? "present in the in-memory credential store (value never shown)" : "missing");
            return Outcome.pass("Resolved " + record.displayName() + " (" + record.environment() + ", "
                    + record.authType() + ")" + (applied.isEmpty() ? "" : "; edited: " + String.join(", ", applied.keySet())));
        }

        private Outcome discover(Map<String, Object> details) {
            URI url = URI.create(record.baseUrl() + "/cds-services");
            ExchangeRecorder.Sent sent = recorder.get(url, Map.of("Accept", "application/json"));
            discovery = sent.exchange();
            details.put("exchanges", List.of(ExchangeView.of(sent.exchange())));
            if (!sent.ok()) {
                return Outcome.fail(describeFailure("Discovery", sent.exchange()));
            }
            JsonNode services;
            try {
                services = mapper.readTree(sent.response().body()).path("services");
            } catch (JsonProcessingException e) {
                return Outcome.fail("Discovery response is not JSON");
            }
            if (!services.isArray()) {
                return Outcome.fail("Discovery response has no services array");
            }
            List<Map<String, Object>> listed = new ArrayList<>();
            for (JsonNode service : services) {
                Map<String, Object> view = new LinkedHashMap<>();
                view.put("id", service.path("id").asText());
                view.put("hook", service.path("hook").asText());
                List<String> keys = new ArrayList<>();
                service.path("prefetch").fieldNames().forEachRemaining(keys::add);
                view.put("prefetchKeys", keys);
                listed.add(view);
                if (serviceId == null && sample.hook().equals(service.path("hook").asText())) {
                    serviceId = service.path("id").asText();
                    prefetchKeys = Set.copyOf(keys);
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
            AuthType authType = record.authType() == null ? AuthType.NONE : record.authType();
            details.put("authType", authType.name());
            switch (authType) {
                case NONE -> {
                    return Outcome.pass("The connection uses no authentication");
                }
                case OAUTH2_CLIENT_CREDENTIALS -> {
                    return clientCredentials(details);
                }
                case CDS_HOOKS_JWT -> {
                    return cdsHooksJwt(details);
                }
                default -> {
                    return Outcome.fail("The workbench does not exercise " + authType + " connections yet");
                }
            }
        }

        private Outcome clientCredentials(Map<String, Object> details) {
            Optional<String> secret = payers.credentials().resolve(record.credentialRef());
            if (secret.isEmpty()) {
                return Outcome.fail("No client secret in the credential store for " + record.credentialRef());
            }
            String basic = Base64.getEncoder().encodeToString(
                    (form(record.clientId()) + ":" + form(secret.get())).getBytes(StandardCharsets.UTF_8));
            String body = "grant_type=client_credentials"
                    + (record.scopes().isEmpty() ? "" : "&scope=" + form(String.join(" ", record.scopes())));
            ExchangeRecorder.Sent sent = recorder.post(URI.create(record.tokenEndpoint()), Map.of(
                    "Authorization", "Basic " + basic,
                    "Content-Type", "application/x-www-form-urlencoded",
                    "Accept", "application/json"), body);
            details.put("exchanges", List.of(ExchangeView.of(sent.exchange())));
            JsonNode json = sent.response() == null ? null : readJson(sent.response().body());
            if (json != null) {
                List<String> scopes = json.hasNonNull("scope") ? List.of(json.get("scope").asText().split(" ")) : List.of();
                tokenResponse = new TokenResponseMetadata(json.hasNonNull("access_token"),
                        text(json, "token_type"), json.hasNonNull("expires_in") ? json.get("expires_in").asLong() : null,
                        scopes, text(json, "error"), text(json, "error_description"));
                details.put("token", Map.of(
                        "accessTokenPresent", tokenResponse.accessTokenPresent(),
                        "tokenType", String.valueOf(tokenResponse.tokenType()),
                        "expiresInSeconds", String.valueOf(tokenResponse.expiresInSeconds())));
            }
            if (!sent.ok()) {
                return Outcome.fail(describeFailure("Token request", sent.exchange()));
            }
            if (json == null || !json.hasNonNull("access_token")) {
                return Outcome.fail("Token response has no access_token");
            }
            authorization = "Bearer " + json.get("access_token").asText();
            return Outcome.pass("Got a " + text(json, "token_type") + " access token for client " + record.clientId()
                    + " (expires in " + text(json, "expires_in") + " s; value hidden)");
        }

        private Outcome cdsHooksJwt(Map<String, Object> details) {
            Optional<String> pem = payers.credentials().resolve(record.credentialRef());
            if (pem.isEmpty()) {
                return Outcome.fail("No signing key in the credential store for " + record.credentialRef());
            }
            String target = serviceUrl();
            String aud = isSet(request.connection().audOverride()) ? request.connection().audOverride().trim() : target;
            String jwt;
            try {
                jwt = new JwtSigner().cdsHooksJwt(record, PemKeys.readPrivateKey(pem.get()), URI.create(aud));
            } catch (RuntimeException e) {
                return Outcome.fail("Could not sign the client JWT: " + e.getMessage());
            }
            String[] parts = jwt.split("\\.");
            details.put("jwtHeader", decode(parts[0]));
            details.put("jwtClaims", decode(parts[1]));
            details.put("requestUrl", target);
            authorization = "Bearer " + jwt;
            clientJwt = claimsOf(parts[0], parts[1]);
            boolean exact = aud.equals(target);
            details.put("audMatchesRequestUrl", exact);
            return Outcome.pass("Signed a CDS Hooks client JWT as " + record.clientId() + " (kid " + record.keyId()
                    + ") for aud " + aud + (exact ? "" : ", which is not the URL it will be sent to (" + target + ")"));
        }

        private Outcome sendHook(Map<String, Object> details) {
            PrefetchVariant variant = prefetchKeys.contains("coverageBundle") ? PrefetchVariant.PAYER_B : PrefetchVariant.STANDARD;
            Sample loaded = samples.load(sample.id(), variant).withNewHookInstance();
            hookBody = loaded.toJsonString();
            details.put("sample", sample.id());
            details.put("prefetchVariant", variant.name());
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Accept", "application/json");
            if (authorization != null) {
                headers.put("Authorization", authorization);
            }
            ExchangeRecorder.Sent sent = recorder.post(URI.create(serviceUrl()), headers, hookBody);
            hookResponses.add(new HookResponse(serviceId, sample.hook(), sample.id(), sent.exchange(), clientJwt));
            details.put("exchanges", List.of(ExchangeView.of(sent.exchange())));
            if (!sent.ok()) {
                return Outcome.fail(describeFailure("Hook call to " + serviceId, sent.exchange()));
            }
            return Outcome.pass("HTTP " + sent.exchange().status() + " from " + serviceId + " in "
                    + sent.exchange().latency().toMillis() + " ms");
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
            List<Card> cards = new ArrayList<>();
            List<SystemAction> actions = new ArrayList<>();
            try {
                for (JsonNode card : json.path("cards")) {
                    cards.add(mapper.treeToValue(card, Card.class));
                }
                for (JsonNode action : json.path("systemActions")) {
                    actions.add(mapper.treeToValue(action, SystemAction.class));
                }
            } catch (JsonProcessingException | IllegalArgumentException e) {
                return Outcome.fail("The client library could not read the response: " + e.getMessage());
            }
            CdsHookResponse response = new CdsHookResponse(cards, actions, json);
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
            recorder.exchanges().forEach(obs::exchange);
            obs.discovery(discovery).tokenResponse(tokenResponse);
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
            details.put("status", outcome.ok() ? "passed" : "failed");
            steps.add(new StepResult(id, startedAt, Duration.ofNanos(System.nanoTime() - start), outcome.ok(),
                    outcome.summary(), details));
            return outcome.ok();
        }

        private String serviceUrl() {
            return record.baseUrl() + "/cds-services/" + serviceId;
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

    private static String describeFailure(String what, HttpExchange exchange) {
        if (!exchange.responded()) {
            return what + " got no response: " + exchange.transportError();
        }
        return what + " returned HTTP " + exchange.status();
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
                    text(h, "kid"));
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
        return json.hasNonNull(field) ? json.get(field).asText() : null;
    }

    private static String form(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
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
