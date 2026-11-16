package io.github.dflippojr.payerworkbench.app;

import io.github.dflippojr.payerworkbench.core.JwtClaims;
import io.github.dflippojr.payerworkbench.core.RedactedConnection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The JSON form of the runner's own records, built field by field, for a step's details (#360, owner amendment of
 * 2026-11-16, snapshot first). A step's details hold only strings, kept JDK scalars, maps and lists, so the snapshot every
 * entry point takes reads them as they are, and the runner never serialises objects before they are redacted. Each map
 * has the fields, in the order and with the values, that the record's JSON form had, so a run is served as before.
 */
final class StepDetails {

    private StepDetails() {
    }

    static Map<String, Object> of(ExchangeView e) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("method", e.method());
        out.put("url", e.url());
        out.put("status", e.status());
        out.put("latencyMs", e.latencyMs());
        out.put("requestHeaders", e.requestHeaders());
        out.put("requestBody", e.requestBody());
        out.put("responseHeaders", e.responseHeaders());
        out.put("responseBody", e.responseBody());
        out.put("transportError", e.transportError());
        return out;
    }

    static List<Map<String, Object>> exchanges(List<ExchangeView> views) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ExchangeView view : views) {
            out.add(of(view));
        }
        return out;
    }

    static Map<String, Object> of(RedactedConnection c) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("payerId", c.payerId());
        out.put("displayName", c.displayName());
        out.put("environment", c.environment() == null ? null : c.environment().name());
        out.put("baseUrl", c.baseUrl());
        out.put("authType", c.authType() == null ? null : c.authType().name());
        out.put("tokenEndpoint", c.tokenEndpoint());
        out.put("clientId", c.clientId());
        out.put("keyId", c.keyId());
        out.put("jwksUrl", c.jwksUrl());
        out.put("tenant", c.tenant());
        out.put("scopes", c.scopes());
        out.put("credentialConfigured", c.credentialConfigured());
        out.put("mtlsConfigured", c.mtlsConfigured());
        out.put("igVersion", c.igVersion());
        out.put("status", c.status() == null ? null : c.status().name());
        return out;
    }

    static Map<String, Object> of(JwtClaims c) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("iss", c.iss());
        out.put("aud", c.aud());
        out.put("exp", text(c.exp()));
        out.put("iat", text(c.iat()));
        out.put("jti", c.jti());
        out.put("kid", c.kid());
        out.put("sub", c.sub());
        return out;
    }

    /** An instant as its JSON form wrote it: ISO-8601 text. */
    private static String text(Instant instant) {
        return instant == null ? null : instant.toString();
    }
}
