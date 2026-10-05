package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An embedded synthetic CDS Hooks / Da Vinci CRD payer on the JDK HTTP server,
 * bound to the loopback interface.
 *
 * <p>Subclasses supply the personality (services, authentication and coverage
 * rules). This class handles the parts every mock shares:
 * <ul>
 *   <li>{@code GET /cds-services} discovery, which advertises the CRD version
 *       in each service's {@code extension} under {@value #IG_VERSION_EXTENSION};</li>
 *   <li>{@code POST /cds-services/{id}}: authenticate, validate the request
 *       shape, then hand off to {@link #handleHook};</li>
 *   <li>the fault admin endpoint, {@code /admin/faults}, which bypasses HTTP response faults
 *       (certificate faults still affect its TLS handshake);</li>
 *   <li>the request-level {@link Fault faults}. Response bodies stay realistic;
 *       a faulted response carries an {@value #FAULT_HEADER} header naming the fault.</li>
 * </ul>
 *
 * <p>Admin endpoint: {@code GET /admin/faults} lists faults and their state;
 * {@code POST /admin/faults/{id}} enables one ({@code ?delayMs=N} sets the
 * {@code slow-response} delay); {@code DELETE /admin/faults/{id}} disables one;
 * {@code DELETE /admin/faults} disables all. It has no authentication, which is
 * one reason the server only listens on loopback.
 */
public abstract class MockPayer implements AutoCloseable {

    /** Discovery {@code extension} key carrying the CRD IG version the payer implements (a mock convention). */
    public static final String IG_VERSION_EXTENSION = "davinci-crd.ig-version";

    /** Response header naming the {@link Fault#id()} that shaped the response. */
    public static final String FAULT_HEADER = "X-Mock-Fault";

    static final String COVERAGE_INFORMATION_URL =
            "http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information";

    private static final Pattern PREFETCH_TOKEN =
            Pattern.compile("\\{\\{context\\.([A-Za-z]+)(?:\\.([A-Za-z]+)\\.id)?}}");

    protected final ObjectMapper mapper = new ObjectMapper();
    protected final Clock clock;
    private final FaultSettings faults = new FaultSettings();
    private final String configuredPublicBaseUrl;
    private HttpServer server;
    private TestTls tls;

    /** Enables in-memory test TLS before starting the payer. */
    public MockPayer tls(TestTls tls) {
        if (server != null) {
            throw new IllegalStateException("Configure TLS before starting");
        }
        this.tls = Objects.requireNonNull(tls);
        return this;
    }
    private ExecutorService executor;

    /**
     * @param clock time source for token expiry and coverage dates
     * @param publicBaseUrl the base URL clients are told to use, if it differs from
     *     {@code http://localhost:<port>} (e.g. behind a proxy); used for audience checks.
     *     {@code null} for the default.
     */
    protected MockPayer(Clock clock, String publicBaseUrl) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.configuredPublicBaseUrl = publicBaseUrl == null ? null : trimTrailingSlash(publicBaseUrl);
    }

    /** The payer's name as shown to users, e.g. on card sources. */
    public abstract String displayName();

    /** The Da Vinci CRD IG version this payer declares. */
    public abstract String igVersion();

    /** The services listed by discovery, in order. */
    public abstract List<ServiceDefinition> services();

    /**
     * Checks the credential on a hook call.
     *
     * @throws HttpError (usually 401) if the request must be rejected
     */
    protected abstract void authenticate(Request request);

    /** Builds the response to a hook call that passed authentication and shape checks. */
    protected abstract ObjectNode handleHook(ServiceDefinition service, ObjectNode hookRequest);

    /** Handles any payer-specific endpoint, such as a token endpoint; {@code null} if none matches. */
    protected Response handleOther(Request request) {
        return null;
    }

    /** Starts listening on {@code port} on loopback; {@code 0} picks an ephemeral port. */
    public synchronized MockPayer start(int port) throws IOException {
        if (server != null) {
            throw new IllegalStateException(displayName() + " is already running on port " + port());
        }
        InetSocketAddress address = new InetSocketAddress("127.0.0.1", port);
        HttpServer created;
        if (tls == null) {
            created = HttpServer.create(address, 0);
        } else {
            HttpsServer https = HttpsServer.create(address, 0);
            https.setHttpsConfigurator(new HttpsConfigurator(tls.serverContext(faults)));
            created = https;
        }
        executor = Executors.newVirtualThreadPerTaskExecutor();
        created.setExecutor(executor);
        created.createContext("/", this::handle);
        created.start();
        server = created;
        return this;
    }

    /** Stops the server, abandoning in-flight requests (including ones held by {@code slow-response}). */
    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            executor.shutdownNow();
            server = null;
            executor = null;
        }
    }

    @Override
    public void close() {
        stop();
    }

    public synchronized int port() {
        if (server == null) {
            throw new IllegalStateException(displayName() + " is not running");
        }
        return server.getAddress().getPort();
    }

    /** Where clients reach this payer, using HTTP or HTTPS as configured. Use as a {@code ConnectionRecord} base URL. */
    public String baseUrl() {
        return tls == null ? "http://localhost:" + port() : "https://127.0.0.1:" + port();
    }

    /** The base URL the payer believes it is published at; audience checks are made against this. */
    public String publicBaseUrl() {
        return configuredPublicBaseUrl != null ? configuredPublicBaseUrl : baseUrl();
    }

    /** The programmatic fault switchboard; the admin endpoint changes the same settings. */
    public FaultSettings faults() {
        return faults;
    }

    // ---- request handling ----

    private void handle(HttpExchange exchange) {
        try (exchange) {
            Response response;
            try {
                response = route(Request.from(exchange));
            } catch (HttpError e) {
                response = e.response(mapper);
            } catch (RuntimeException e) {
                response = Response.json(mapper, 500, error("server_error", "Unexpected error: " + e));
            }
            send(exchange, response);
        } catch (IOException e) {
            // The client went away; nothing to report it to.
        }
    }

    private Response route(Request request) {
        String path = request.path();
        if (path.equals("/admin/faults") || path.startsWith("/admin/faults/")) {
            return admin(request);
        }
        boolean slowed = faults.isEnabled(Fault.SLOW_RESPONSE) && isHookCall(request);
        if (slowed) {
            pause(faults.slowResponseDelay());
        }
        Response response = dispatch(request);
        return slowed && !response.headers().containsKey(FAULT_HEADER)
                ? response.withFault(Fault.SLOW_RESPONSE)
                : response;
    }

    /** {@code POST /cds-services/{id}}: the only requests {@link Fault#SLOW_RESPONSE} holds. */
    private static boolean isHookCall(Request request) {
        return request.method().equals("POST")
                && request.path().startsWith("/cds-services/")
                && request.path().length() > "/cds-services/".length();
    }

    private Response dispatch(Request request) {
        String path = request.path();
        if (path.equals("/cds-services") || path.equals("/cds-services/")) {
            requireMethod(request, "GET");
            return discovery();
        }
        if (path.startsWith("/cds-services/")) {
            String id = path.substring("/cds-services/".length());
            ServiceDefinition service = services().stream()
                    .filter(s -> s.id().equals(id))
                    .findFirst()
                    .orElseThrow(() -> new HttpError(404, "not_found", "No CDS service with id '" + id + "'"));
            requireMethod(request, "POST");
            return hook(service, request);
        }
        Response other = handleOther(request);
        if (other != null) {
            return other;
        }
        throw new HttpError(404, "not_found", "No resource at " + path);
    }

    private Response discovery() {
        if (faults.isEnabled(Fault.DISCOVERY_500)) {
            return Response.json(mapper, 500, error("server_error", "Service catalog is temporarily unavailable"))
                    .withFault(Fault.DISCOVERY_500);
        }
        ObjectNode root = mapper.createObjectNode();
        ArrayNode list = root.putArray("services");
        for (ServiceDefinition service : services()) {
            ObjectNode node = list.addObject();
            node.put("hook", service.hook());
            node.put("title", service.title());
            node.put("description", service.description());
            node.put("id", service.id());
            ObjectNode prefetch = node.putObject("prefetch");
            service.prefetch().forEach(prefetch::put);
            node.putObject("extension").put(IG_VERSION_EXTENSION, igVersion());
        }
        return Response.json(mapper, 200, root);
    }

    private Response hook(ServiceDefinition service, Request request) {
        authenticate(request);
        ObjectNode hookRequest = parseObject(request.body());
        if (!service.hook().equals(hookRequest.path("hook").asText())) {
            throw new HttpError(400, "invalid_request", "Service '" + service.id() + "' handles hook '"
                    + service.hook() + "', got '" + hookRequest.path("hook").asText() + "'");
        }
        if (hookRequest.path("hookInstance").asText().isBlank()) {
            throw new HttpError(400, "invalid_request", "hookInstance is required");
        }
        JsonNode context = hookRequest.path("context");
        if (!context.isObject() || context.path("patientId").asText().isBlank()) {
            throw new HttpError(400, "invalid_request", "context.patientId is required");
        }
        if (!"Bundle".equals(context.path("draftOrders").path("resourceType").asText())) {
            throw new HttpError(400, "invalid_request", "context.draftOrders must be a FHIR Bundle");
        }
        if (faults.isEnabled(Fault.PREFETCH_MISSING_400)) {
            List<String> missing = missingPrefetch(service, context, hookRequest.path("prefetch"));
            if (!missing.isEmpty()) {
                ObjectNode body = error("prefetch_missing",
                        "Required prefetch not supplied: " + String.join(", ", missing));
                body.putPOJO("missing", missing);
                return Response.json(mapper, 400, body).withFault(Fault.PREFETCH_MISSING_400);
            }
        }
        ObjectNode response = handleHook(service, hookRequest);
        if (faults.isEnabled(Fault.MALFORMED_CARD)) {
            for (JsonNode card : response.path("cards")) {
                ((ObjectNode) card).remove(List.of("summary", "indicator"));
            }
            return Response.json(mapper, 200, response).withFault(Fault.MALFORMED_CARD);
        }
        if (faults.isEnabled(Fault.COVERAGE_INFO_INCOMPLETE) && "order-sign".equals(service.hook())) {
            return Response.json(mapper, 200, response).withFault(Fault.COVERAGE_INFO_INCOMPLETE);
        }
        return Response.json(mapper, 200, response);
    }

    /**
     * Declared prefetch keys the client left out although every token in their
     * template resolves from the context (CDS Hooks lets clients omit the rest).
     */
    static List<String> missingPrefetch(ServiceDefinition service, JsonNode context, JsonNode prefetch) {
        List<String> missing = new ArrayList<>();
        service.prefetch().forEach((key, template) -> {
            JsonNode supplied = prefetch.path(key);
            if ((supplied.isMissingNode() || supplied.isNull()) && resolvable(template, context)) {
                missing.add(key);
            }
        });
        return missing;
    }

    private static boolean resolvable(String template, JsonNode context) {
        Matcher matcher = PREFETCH_TOKEN.matcher(template);
        while (matcher.find()) {
            JsonNode value = context.path(matcher.group(1));
            if (value.isMissingNode() || value.isNull() || (value.isTextual() && value.asText().isBlank())) {
                return false;
            }
            String resourceType = matcher.group(2);
            if (resourceType != null && draftOrders(value).stream()
                    .noneMatch(r -> resourceType.equals(r.path("resourceType").asText()))) {
                return false;
            }
        }
        return true;
    }

    private Response admin(Request request) {
        String rest = request.path().substring("/admin/faults".length());
        if (rest.isEmpty() || rest.equals("/")) {
            switch (request.method()) {
                case "GET" -> { }
                case "DELETE" -> faults.clear();
                default -> throw new HttpError(405, "method_not_allowed", "Use GET or DELETE");
            }
            return Response.json(mapper, 200, faultState());
        }
        String id = rest.substring(1);
        Fault fault = Fault.fromId(id).orElseThrow(() -> new HttpError(404, "not_found",
                "Unknown fault '" + id + "'"));
        switch (request.method()) {
            case "POST", "PUT" -> {
                String delayMs = request.queryParameter("delayMs");
                if (fault == Fault.SLOW_RESPONSE && delayMs != null) {
                    try {
                        faults.slowResponse(Duration.ofMillis(Long.parseLong(delayMs)));
                    } catch (IllegalArgumentException e) {
                        throw new HttpError(400, "invalid_request", "delayMs must be a non-negative integer");
                    }
                } else {
                    faults.enable(fault);
                }
            }
            case "DELETE" -> faults.disable(fault);
            default -> throw new HttpError(405, "method_not_allowed", "Use POST, PUT or DELETE");
        }
        return Response.json(mapper, 200, faultState());
    }

    private ObjectNode faultState() {
        ObjectNode root = mapper.createObjectNode();
        root.put("payer", displayName());
        ArrayNode list = root.putArray("faults");
        for (Fault fault : Fault.values()) {
            ObjectNode node = list.addObject().put("id", fault.id()).put("enabled", faults.isEnabled(fault));
            if (fault == Fault.SLOW_RESPONSE) {
                node.put("delayMs", faults.slowResponseDelay().toMillis());
            }
        }
        return root;
    }

    // ---- helpers for subclasses ----

    /** The resources in a {@code draftOrders} Bundle. */
    static List<ObjectNode> draftOrders(JsonNode draftOrders) {
        List<ObjectNode> orders = new ArrayList<>();
        for (JsonNode entry : draftOrders.path("entry")) {
            if (entry.path("resource").isObject()) {
                orders.add((ObjectNode) entry.path("resource"));
            }
        }
        return orders;
    }

    /** The first coding's code on an order (DeviceRequest, ServiceRequest or MedicationRequest), or {@code null}. */
    static String orderCode(JsonNode order) {
        for (String field : List.of("codeCodeableConcept", "code", "medicationCodeableConcept")) {
            JsonNode code = order.path(field).path("coding").path(0).path("code");
            if (code.isTextual()) {
                return code.asText();
            }
        }
        return null;
    }

    /** {@code ResourceType/id} of an order, or {@code ResourceType} alone if it has no id. */
    static String orderLabel(JsonNode order) {
        String type = order.path("resourceType").asText("Resource");
        return order.hasNonNull("id") ? type + "/" + order.get("id").asText() : type;
    }

    /** The first Coverage in any of the given prefetch Bundles, else the order's own {@code insurance}. */
    static String coverageReference(JsonNode order, JsonNode... bundles) {
        for (JsonNode bundle : bundles) {
            for (JsonNode entry : bundle.path("entry")) {
                JsonNode resource = entry.path("resource");
                if ("Coverage".equals(resource.path("resourceType").asText()) && resource.hasNonNull("id")) {
                    return "Coverage/" + resource.get("id").asText();
                }
            }
        }
        JsonNode insurance = order.path("insurance").path(0).path("reference");
        return insurance.isTextual() ? insurance.asText() : null;
    }

    /**
     * A copy of {@code order} carrying one {@code ext-coverage-information} extension.
     *
     * @param assertionIdUrl {@code coverage-assertion-id} (CRD 2.x) or {@code identifier} (the HL7 RI's form)
     */
    ObjectNode withCoverageInformation(JsonNode order, CoverageDetermination determination, String coverage,
                                       String assertionIdUrl, String assertionId) {
        ObjectNode extension = mapper.createObjectNode().put("url", COVERAGE_INFORMATION_URL);
        ArrayNode parts = extension.putArray("extension");
        if (coverage != null) {
            parts.addObject().put("url", "coverage").putObject("valueReference").put("reference", coverage);
        }
        boolean incomplete = faults.isEnabled(Fault.COVERAGE_INFO_INCOMPLETE);
        parts.addObject().put("url", "covered").put("valueCode", incomplete ? "invalid-covered" : determination.covered());
        if (!"not-covered".equals(determination.covered())) {
            parts.addObject().put("url", "pa-needed").put("valueCode", determination.paNeeded());
        }
        if ("conditional".equals(determination.covered())) {
            parts.addObject().put("url", "info-needed").put("valueCode", "detail-code");
        }
        for (String doc : determination.docNeeded()) {
            parts.addObject().put("url", "doc-needed").put("valueCode", doc);
        }
        parts.addObject().put("url", "date").put("valueDate", LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC).toString());
        if (!incomplete) {
            parts.addObject().put("url", assertionIdUrl).put("valueString", assertionId);
        }

        ObjectNode copy = order.deepCopy();
        JsonNode existing = copy.path("extension");
        ArrayNode extensions = existing.isArray() ? (ArrayNode) existing : copy.putArray("extension");
        extensions.add(extension);
        return copy;
    }

    /** A card with this payer as {@code source.label}; {@code uuid} is derived from {@code seed} so output is repeatable. */
    ObjectNode card(String seed, String summary, String indicator, String detail, String topicSystem,
                    String topicCode, String topicDisplay) {
        ObjectNode card = mapper.createObjectNode();
        card.put("uuid", UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString());
        card.put("summary", summary);
        card.put("indicator", indicator);
        if (detail != null) {
            card.put("detail", detail);
        }
        ObjectNode source = card.putObject("source");
        source.put("label", displayName());
        source.putObject("topic").put("system", topicSystem).put("code", topicCode).put("display", topicDisplay);
        return card;
    }

    ObjectNode error(String code, String description) {
        return mapper.createObjectNode().put("error", code).put("error_description", description);
    }

    ObjectNode parseObject(String body) {
        try {
            JsonNode node = mapper.readTree(body);
            if (node instanceof ObjectNode object) {
                return object;
            }
        } catch (IOException e) {
            // fall through
        }
        throw new HttpError(400, "invalid_request", "Request body must be a JSON object");
    }

    private static void requireMethod(Request request, String method) {
        if (!request.method().equals(method)) {
            throw new HttpError(405, "method_not_allowed", "Use " + method);
        }
    }

    private static void pause(Duration delay) {
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HttpError(503, "unavailable", "Server is shutting down");
        }
    }

    private static void send(HttpExchange exchange, Response response) throws IOException {
        byte[] bytes = response.body().getBytes(StandardCharsets.UTF_8);
        response.headers().forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(response.status(), bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    // ---- small HTTP types ----

    /**
     * One discovery entry.
     *
     * @param prefetch prefetch key to FHIR query template, in the order advertised
     */
    public record ServiceDefinition(String id, String hook, String title, String description,
                                    Map<String, String> prefetch) {
        public ServiceDefinition {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(hook, "hook");
            prefetch = Collections.unmodifiableMap(new LinkedHashMap<>(prefetch));
        }
    }

    /** An incoming request with its body already read. Header lookup is case-insensitive. */
    protected record Request(String method, String path, String rawQuery, Map<String, String> headers, String body) {

        static Request from(HttpExchange exchange) throws IOException {
            Map<String, String> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((name, values) ->
                    headers.put(name.toLowerCase(Locale.ROOT), values.isEmpty() ? "" : values.get(0)));
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            return new Request(exchange.getRequestMethod().toUpperCase(Locale.ROOT),
                    exchange.getRequestURI().getPath(), exchange.getRequestURI().getRawQuery(), headers, body);
        }

        public String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }

        /** The value after an {@code Authorization: Bearer} prefix, or {@code null}. */
        public String bearerToken() {
            String value = header("Authorization");
            if (value == null || !value.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return null;
            }
            String token = value.substring(7).trim();
            return token.isEmpty() ? null : token;
        }

        public String queryParameter(String name) {
            return formParameters(rawQuery).get(name);
        }

        /** Parses {@code application/x-www-form-urlencoded} text; the first value of each name wins. */
        static Map<String, String> formParameters(String encoded) {
            Map<String, String> params = new LinkedHashMap<>();
            if (encoded == null || encoded.isEmpty()) {
                return params;
            }
            for (String pair : encoded.split("&")) {
                int eq = pair.indexOf('=');
                String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                params.putIfAbsent(name, value);
            }
            return params;
        }
    }

    /** A response to send: status, extra headers and a JSON body. */
    protected record Response(int status, Map<String, String> headers, String body) {

        static Response json(ObjectMapper mapper, int status, JsonNode body) {
            try {
                return new Response(status, Map.of(), mapper.writeValueAsString(body));
            } catch (IOException e) {
                throw new IllegalStateException("Could not serialize response", e);
            }
        }

        Response withHeader(String name, String value) {
            Map<String, String> copy = new LinkedHashMap<>(headers);
            copy.put(name, value);
            return new Response(status, Collections.unmodifiableMap(copy), body);
        }

        Response withFault(Fault fault) {
            return withHeader(FAULT_HEADER, fault.id());
        }
    }

    /** Thrown by handlers to reply with an OAuth-style {@code {"error", "error_description"}} body. */
    protected static final class HttpError extends RuntimeException {

        private final int status;
        private final String code;
        private final Map<String, String> headers = new LinkedHashMap<>();

        public HttpError(int status, String code, String description) {
            super(description, null, false, false);
            this.status = status;
            this.code = code;
        }

        public HttpError header(String name, String value) {
            headers.put(name, value);
            return this;
        }

        public HttpError fault(Fault fault) {
            return header(FAULT_HEADER, fault.id());
        }

        public int status() {
            return status;
        }

        Response response(ObjectMapper mapper) {
            ObjectNode body = mapper.createObjectNode().put("error", code).put("error_description", getMessage());
            Response response = Response.json(mapper, status, body);
            for (Map.Entry<String, String> header : headers.entrySet()) {
                response = response.withHeader(header.getKey(), header.getValue());
            }
            return response;
        }
    }
}
