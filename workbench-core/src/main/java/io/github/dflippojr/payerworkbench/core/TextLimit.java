package io.github.dflippojr.payerworkbench.core;

/**
 * Cuts payer-supplied text before a run shows or keeps it. The byte and JSON-value limits bound a
 * response, not one string in it, so without this a single 4 MiB card summary would make a 4 MiB run.
 */
public final class TextLimit {

    /** The most characters of one payer-supplied string kept in a step's details or an evidence line. */
    public static final int MAX_CHARS = 1024;

    /** The most characters of each text field of a {@link Finding}. */
    public static final int MAX_FINDING_CHARS = 8 * 1024;

    /** Appended where text was cut. */
    public static final String ELLIPSIS = "…";

    private TextLimit() {
    }

    /** {@code text} cut to {@link #MAX_CHARS}; {@code null} stays {@code null}. */
    public static String cut(String text) {
        return cut(text, MAX_CHARS);
    }

    /** {@code text}, or its first {@code max} characters and {@link #ELLIPSIS} when longer; never splits a surrogate pair. */
    public static String cut(String text, int max) {
        if (text == null || text.length() <= max) {
            return text;
        }
        int end = Character.isHighSurrogate(text.charAt(max - 1)) ? max - 1 : max;
        return text.substring(0, end) + ELLIPSIS;
    }
}
