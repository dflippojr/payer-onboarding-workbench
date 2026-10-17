package io.github.dflippojr.payerworkbench.app;

import java.io.IOException;
import java.net.http.HttpHeaders;
import java.util.Map;

/**
 * A payer response the workbench would not take in full: its body ran past
 * {@code workbench.max-response-bytes}, or held more JSON values than
 * {@code workbench.max-response-json-values}. The exception carries what did arrive: the status,
 * the headers and the body up to the byte limit, or a short prefix of a body with too many values.
 */
final class ResponseTooLargeException extends IOException {
    /** What ran past its limit. */
    enum Measure { BYTES, JSON_VALUES }

    /** How much of a body with too many JSON values is kept, so nothing downstream parses it whole. */
    static final int JSON_VALUES_PREFIX_CHARS = 8 * 1024;

    private final Measure measure;
    private final long limit;
    private final long bytesRead;
    private final int statusCode;
    private final transient HttpHeaders headers;
    private final String truncatedBody;

    /**
     * A body that ran past the byte limit.
     *
     * @param bytesRead     bytes received before the client stopped, a little past {@code limit}
     * @param truncatedBody the first {@code limit} bytes as the caller's body handler read them,
     *                      or {@code null} if that handler does not produce a string
     */
    ResponseTooLargeException(long limit, long bytesRead, int statusCode, HttpHeaders headers, String truncatedBody) {
        this(Measure.BYTES, limit, bytesRead, statusCode, headers, truncatedBody,
                "Response body exceeded the " + describe(limit) + " limit (workbench.max-response-bytes); "
                        + "stopped reading after " + bytesRead + " bytes");
    }

    private ResponseTooLargeException(Measure measure, long limit, long bytesRead, int statusCode, HttpHeaders headers,
                                      String truncatedBody, String message) {
        super(message);
        this.measure = measure;
        this.limit = limit;
        this.bytesRead = bytesRead;
        this.statusCode = statusCode;
        this.headers = headers;
        this.truncatedBody = truncatedBody;
    }

    /** A body, read in full, that holds more than {@code limit} JSON values; only a short prefix of it is kept. */
    static ResponseTooLargeException jsonValues(long limit, long bytesRead, int statusCode, HttpHeaders headers,
                                                String body) {
        return new ResponseTooLargeException(Measure.JSON_VALUES, limit, bytesRead, statusCode, headers,
                body.length() <= JSON_VALUES_PREFIX_CHARS ? body : body.substring(0, JSON_VALUES_PREFIX_CHARS),
                "Response body holds more than " + limit + " JSON values (workbench.max-response-json-values), "
                        + "so the workbench did not parse it");
    }

    /** The exception in {@code error}'s cause chain, or {@code null} if there is none. */
    static ResponseTooLargeException in(Throwable error) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof ResponseTooLargeException e) {
                return e;
            }
        }
        return null;
    }

    /** {@code 4 MiB}, {@code 512 KiB} or {@code 1000 bytes}. */
    static String describe(long bytes) {
        if (bytes >= 1024 * 1024 && bytes % (1024 * 1024) == 0) {
            return bytes / (1024 * 1024) + " MiB";
        }
        if (bytes >= 1024 && bytes % 1024 == 0) {
            return bytes / 1024 + " KiB";
        }
        return bytes + " bytes";
    }

    Measure measure() {
        return measure;
    }

    /** The limit in words: {@code 4 MiB} or {@code 100000 JSON values}. */
    String describeLimit() {
        return measure == Measure.BYTES ? describe(limit) : limit + " JSON values";
    }

    /** The setting that holds the limit. */
    String setting() {
        return measure == Measure.BYTES ? "workbench.max-response-bytes" : "workbench.max-response-json-values";
    }

    long limit() {
        return limit;
    }

    long bytesRead() {
        return bytesRead;
    }

    int statusCode() {
        return statusCode;
    }

    HttpHeaders headers() {
        return headers == null ? HttpHeaders.of(Map.of(), (k, v) -> true) : headers;
    }

    String truncatedBody() {
        return truncatedBody;
    }

    /** The note appended to a recorded body that was cut. */
    String note() {
        return measure == Measure.BYTES ? "[truncated at " + limit + " bytes]"
                : "[not parsed: more than " + limit + " JSON values; kept the first " + JSON_VALUES_PREFIX_CHARS
                        + " characters]";
    }
}
