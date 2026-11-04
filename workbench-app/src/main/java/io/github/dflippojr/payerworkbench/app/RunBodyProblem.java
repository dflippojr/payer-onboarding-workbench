package io.github.dflippojr.payerworkbench.app;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.exc.MismatchedInputException;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * Says what is wrong with a {@code POST /api/runs} body that couldn't be bound to a {@link RunRequest}.
 *
 * <p>The body can hold a credential and the detail reaches the caller and the screen, so the text is built only from
 * the bound field's path and its schema. Jackson's own message quotes the submitted value, so it is never used. A
 * syntax error can carry the name of a field the record ignores, so its path isn't used either.
 */
final class RunBodyProblem {
    static final String NOT_AN_OBJECT = "Request body must be a JSON object";
    static final String NOT_JSON = "Request body is not valid JSON";

    private RunBodyProblem() {
    }

    /** @param cause the {@code HttpMessageNotReadableException}'s cause; null when the body is empty or {@code null} */
    static String describe(Throwable cause) {
        if (cause == null) { return NOT_AN_OBJECT; }
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (t instanceof RunRequest.InvalidField invalid) { return invalid.getMessage(); }
        }
        if (!(cause instanceof DatabindException mapping)) { return NOT_JSON; }
        String field = fieldPath(mapping);
        if (field.isEmpty()) { return NOT_AN_OBJECT; }
        if (mapping instanceof MismatchedInputException mismatch && mismatch.getTargetType() != null
                && mismatch.getTargetType().isEnum()) {
            return field + " must be one of " + constants(mismatch.getTargetType());
        }
        return field + " has the wrong type";
    }

    private static String fieldPath(DatabindException e) {
        StringBuilder path = new StringBuilder();
        for (JacksonException.Reference step : e.getPath()) {
            if (step.getPropertyName() != null) {
                path.append(path.isEmpty() ? "" : ".").append(step.getPropertyName());
            } else {
                path.append('[').append(step.getIndex()).append(']');
            }
        }
        return path.toString();
    }

    private static String constants(Class<?> enumType) {
        return Arrays.stream(enumType.getEnumConstants()).map(c -> ((Enum<?>) c).name()).collect(Collectors.joining(", "));
    }
}
