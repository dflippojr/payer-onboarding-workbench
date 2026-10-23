package io.github.dflippojr.payerworkbench.app;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Reads a token response's {@code expires_in} the way the router SDK does after fhir-crd-router#105:
 * a JSON number or a numeric string ({@code "300"}, trimmed) that is a positive whole number of
 * seconds. Anything else ({@code "abc"}, {@code "1.5"}, zero, negative, boolean, object, array) has no
 * usable lifetime. Jackson's {@code asLong()} would turn each of those into a plausible number (#177).
 */
final class ExpiresIn {

    private ExpiresIn() {
    }

    /** The lifetime in seconds, or {@code null} if {@code value} is missing or not usable. */
    static Long seconds(JsonNode value) {
        Long seconds = null;
        if (value != null && value.isNumber()) {
            seconds = wholeNumber(value);
        } else if (value != null && value.isTextual()) {
            seconds = parse(value.textValue().trim());
        }
        return seconds != null && seconds > 0 ? seconds : null;
    }

    private static Long wholeNumber(JsonNode number) {
        try {
            return number.decimalValue().longValueExact();
        } catch (ArithmeticException | NumberFormatException e) {
            return null; // a fraction, beyond a long, or a NaN or infinity that no JSON text holds
        }
    }

    private static Long parse(String text) {
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
