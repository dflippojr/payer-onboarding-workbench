package io.github.dflippojr.payerworkbench.app;

import java.io.IOException;
import java.net.http.HttpHeaders;
import java.util.Map;

/**
 * A payer response whose body ran past {@code workbench.max-response-bytes}. The client stopped
 * reading at the limit, so the exception carries what did arrive: the status, the headers and the
 * body up to the limit.
 */
final class ResponseTooLargeException extends IOException {
    private final long limit;
    private final long bytesRead;
    private final int statusCode;
    private final transient HttpHeaders headers;
    private final String truncatedBody;

    /**
     * @param bytesRead     bytes received before the client stopped, a little past {@code limit}
     * @param truncatedBody the first {@code limit} bytes as the caller's body handler read them,
     *                      or {@code null} if that handler does not produce a string
     */
    ResponseTooLargeException(long limit, long bytesRead, int statusCode, HttpHeaders headers, String truncatedBody) {
        super("Response body exceeded the " + describe(limit) + " limit (workbench.max-response-bytes); "
                + "stopped reading after " + bytesRead + " bytes");
        this.limit = limit;
        this.bytesRead = bytesRead;
        this.statusCode = statusCode;
        this.headers = headers;
        this.truncatedBody = truncatedBody;
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

    /** The note appended to a recorded body that was cut at the limit. */
    String note() {
        return "[truncated at " + limit + " bytes]";
    }
}
