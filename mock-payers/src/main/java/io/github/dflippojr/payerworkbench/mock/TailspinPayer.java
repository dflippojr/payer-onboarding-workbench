package io.github.dflippojr.payerworkbench.mock;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Synthetic SMART Backend Services payer; keys and tokens are held in memory only. */
public final class TailspinPayer extends MockPayer {
    public static final String DISPLAY_NAME = "Tailspin Health Plan (synthetic)";
    public static final String IG_VERSION = "2.2.1";
    public static final int DEFAULT_PORT = 8183;
    public static final String TOKEN_PATH = "/oauth/token";
    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String WRONG_AUDIENCE = "https://auth.tailspin-health.example/token";
    private static final Set<JWSAlgorithm> ALGORITHMS = Set.of(JWSAlgorithm.RS384, JWSAlgorithm.ES384);
    private static final List<ServiceDefinition> SERVICES = List.of(
            new ServiceDefinition("order-sign", "order-sign", "Tailspin coverage requirements (order-sign)",
                    "Coverage and prior authorization requirements for orders being signed.", NorthwindPayer.standardPrefetch()),
            new ServiceDefinition("order-select", "order-select", "Tailspin coverage requirements (order-select)",
                    "Early coverage guidance for orders being selected.", NorthwindPayer.standardPrefetch()));
    private final Map<String, URI> clients;
    private final RegisteredJwks verifier;
    private final Map<String, Instant> usedJtis = new ConcurrentHashMap<>();
    private final Map<String, Instant> tokens = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private TailspinPayer(Builder builder) {
        super(builder.clock, builder.publicBaseUrl);
        clients = Map.copyOf(builder.clients);
        verifier = new RegisteredJwks(clients, TailspinPayer::invalidClient);
    }
    public static Builder builder() { return new Builder(); }
    @Override public String displayName() { return DISPLAY_NAME; }
    @Override public String igVersion() { return IG_VERSION; }
    @Override public List<ServiceDefinition> services() { return SERVICES; }
    @Override public synchronized TailspinPayer start(int port) throws IOException {
        super.start(port);
        return this;
    }
    public String tokenEndpoint() { return baseUrl() + TOKEN_PATH; }

    @Override
    protected Response handleOther(Request request) {
        if (!TOKEN_PATH.equals(request.path())) { return null; }
        if (!"POST".equals(request.method())) { throw new HttpError(405, "method_not_allowed", "Use POST"); }
        Map<String, String> form = Request.formParameters(request.body());
        if (!"client_credentials".equals(form.get("grant_type"))) {
            throw new HttpError(400, "unsupported_grant_type", "Use grant_type=client_credentials");
        }
        if (!ASSERTION_TYPE.equals(form.get("client_assertion_type"))) {
            throw invalidClient("client_assertion_type must be " + ASSERTION_TYPE);
        }
        validateAssertion(form.get("client_assertion"), form.get("client_id"));
        Instant now = clock.instant();
        tokens.values().removeIf(exp -> !now.isBefore(exp));
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        tokens.put(token, now.plus(Duration.ofMinutes(5)));
        ObjectNode body = mapper.createObjectNode().put("access_token", token).put("token_type", "Bearer")
                .put("expires_in", 300);
        if (form.containsKey("scope")) { body.put("scope", form.get("scope")); }
        return Response.json(mapper, 200, body).withHeader("Cache-Control", "no-store").withHeader("Pragma", "no-cache");
    }

    private void validateAssertion(String assertion, String clientId) {
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            if (assertion == null) { throw invalidClient("client_assertion is required"); }
            jwt = SignedJWT.parse(assertion);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) { throw invalidClient("client_assertion must be a signed JWT"); }
        if (!ALGORITHMS.contains(jwt.getHeader().getAlgorithm())) { throw invalidClient("alg must be RS384 or ES384"); }
        String issuer = claims.getIssuer();
        if (issuer == null || !clients.containsKey(issuer)) { throw invalidClient("iss is not a registered client id"); }
        if (!issuer.equals(claims.getSubject()) || (clientId != null && !issuer.equals(clientId))) {
            throw invalidClient("iss and sub must equal the registered client id");
        }
        String kid = jwt.getHeader().getKeyID();
        if (kid == null || kid.isBlank()) { throw invalidClient("kid is required"); }
        verifier.verify(jwt, issuer, kid);
        String expected = faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT) ? WRONG_AUDIENCE : publicBaseUrl() + TOKEN_PATH;
        if (!List.of(expected).equals(claims.getAudience())) {
            HttpError error = invalidClient("aud must be exactly '" + expected + "', got " + claims.getAudience());
            throw faults().isEnabled(Fault.WRONG_AUDIENCE_REJECT) ? error.fault(Fault.WRONG_AUDIENCE_REJECT) : error;
        }
        Instant now = clock.instant();
        if (claims.getExpirationTime() == null) { throw invalidClient("exp is required"); }
        Instant exp = claims.getExpirationTime().toInstant();
        if (!now.isBefore(exp) || exp.isAfter(now.plus(Duration.ofMinutes(5)))) {
            throw invalidClient("exp must be in the future and no more than 5 minutes ahead");
        }
        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) { throw invalidClient("jti is required"); }
        usedJtis.values().removeIf(expiry -> !now.isBefore(expiry));
        if (usedJtis.putIfAbsent(issuer + "|" + jti, exp) != null) { throw invalidClient("jti was already used (replay)"); }
    }
    private static HttpError invalidClient(String message) { return new HttpError(401, "invalid_client", message); }

    @Override
    protected void authenticate(Request request) {
        String token = request.bearerToken();
        Instant exp = token == null ? null : tokens.get(token);
        if (exp == null) { throw new HttpError(401, "invalid_token", "Unknown or missing access token"); }
        if (faults().isEnabled(Fault.EXPIRED_TOKEN_401)) {
            throw new HttpError(401, "invalid_token", "The access token expired").fault(Fault.EXPIRED_TOKEN_401);
        }
        if (!clock.instant().isBefore(exp)) { throw new HttpError(401, "invalid_token", "The access token expired"); }
    }
    @Override protected ObjectNode handleHook(ServiceDefinition service, ObjectNode request) {
        return StandardCoverage.response(this, service, request, "TS");
    }

    public static final class Builder {
        private final Map<String, URI> clients = new LinkedHashMap<>();
        private Clock clock = Clock.systemUTC();
        private String publicBaseUrl;
        private Builder() { }
        public Builder client(String clientId, URI jwksUrl) {
            clients.put(Objects.requireNonNull(clientId), Objects.requireNonNull(jwksUrl));
            return this;
        }
        public Builder clock(Clock clock) { this.clock = Objects.requireNonNull(clock); return this; }
        public Builder publicBaseUrl(String url) { publicBaseUrl = url; return this; }
        public TailspinPayer build() { return new TailspinPayer(this); }
    }
    public static void main(String[] args) throws IOException {
        MockPayer payer = launch(args, System.out);
        Runtime.getRuntime().addShutdownHook(new Thread(payer::stop));
    }
    static TailspinPayer launch(String[] args, PrintStream out) throws IOException {
        StandaloneArgs options = StandaloneArgs.parse(args);
        Builder builder = builder().publicBaseUrl(options.single("public-base-url", null));
        for (String client : options.all("client")) {
            int eq = client.indexOf('=');
            if (eq <= 0) { throw new IllegalArgumentException("--client expects ID=JWKS_URL"); }
            builder.client(client.substring(0, eq), URI.create(client.substring(eq + 1)));
        }
        TailspinPayer payer = builder.build();
        options.configureTls(payer);
        payer.start(Integer.parseInt(options.single("port", String.valueOf(DEFAULT_PORT))));
        out.println(DISPLAY_NAME + " listening at " + payer.baseUrl() + " (CRD " + IG_VERSION + ")");
        out.println("  token endpoint: " + payer.tokenEndpoint() + " (private_key_jwt)");
        payer.clients.forEach((id, url) -> out.println("  client id=" + id + " jwks=" + url));
        out.println("  faults: " + payer.baseUrl() + "/admin/faults");
        return payer;
    }
}
