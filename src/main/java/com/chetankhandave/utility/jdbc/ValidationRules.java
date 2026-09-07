package com.chetankhandave.utility.jdbc;

import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Factory methods for commonly used {@link ValidationRule} instances.
 *
 * <p>These rules are intentionally independent of JDBC and database state so
 * they can be reused for validating values before SQL execution.</p>
 */
public final class ValidationRules {

    private ValidationRules() {
        // Prevent instantiation of this utility class.
    }

    /**
     * Requires a string to contain at least one non-whitespace character.
     *
     * @return rule that rejects empty and whitespace-only strings
     */
    public static ValidationRule<String> notBlank() {
        return new ValidationRule<String>(
                value -> !value.trim().isEmpty(),
                "must not be blank");
    }

    /**
     * Restricts the maximum number of Java characters in a string.
     *
     * @param max maximum permitted length, zero or greater
     * @return maximum-length validation rule
     * @throws IllegalArgumentException when {@code max} is negative
     */
    public static ValidationRule<String> maxLength(final int max) {
        if (max < 0) {
            throw new IllegalArgumentException("Maximum length must not be negative");
        }

        return new ValidationRule<String>(
                value -> value.length() <= max,
                "length must not exceed " + max);
    }

    /**
     * Requires the complete String value to match the supplied regular
     * expression.
     *
     * <p>The regular expression is compiled once when the rule is created and
     * {@link java.util.regex.Matcher#matches()} semantics are used, meaning the
     * entire value must match the pattern. This makes the rule suitable for
     * strict allow-list formats such as reference numbers, account identifiers,
     * country codes, and other structurally constrained SQL parameters.</p>
     *
     * @param regex regular expression describing the complete allowed format
     * @return rule that accepts only Strings matching the supplied pattern
     * @throws IllegalArgumentException when {@code regex} is null or blank
     * @throws java.util.regex.PatternSyntaxException when the expression is invalid
     */
    public static ValidationRule<String> matchesPattern(final String regex) {
        if (regex == null || regex.trim().isEmpty()) {
            throw new IllegalArgumentException("Regular expression must not be null or blank");
        }

        final Pattern pattern = Pattern.compile(regex);

        return new ValidationRule<String>(
                value -> pattern.matcher(value).matches(),
                "must match pattern " + regex);
    }

    /**
     * Requires a non-empty String to contain only ASCII letters and digits.
     *
     * <p>Allowed characters are {@code A-Z}, {@code a-z}, and {@code 0-9}.
     * Spaces, punctuation, quotes, angle brackets, tabs, newlines, and other
     * characters are rejected. Use this rule only for fields whose business
     * format genuinely permits this restricted character set.</p>
     *
     * @return rule allowing only one or more ASCII alphanumeric characters
     */
    public static ValidationRule<String> alphanumeric() {
        return new ValidationRule<String>(
                value -> value.matches("[A-Za-z0-9]+"),
                "must contain only alphanumeric characters");
    }

    /**
     * Requires a non-empty String to contain only ASCII letters, digits, and
     * the ordinary space character.
     *
     * <p>Allowed characters are {@code A-Z}, {@code a-z}, {@code 0-9}, and
     * {@code ' '}. Tabs, line breaks, punctuation, quotes, and angle brackets
     * are rejected. Leading, trailing, and repeated ordinary spaces are allowed;
     * combine this rule with additional field-specific validation when those
     * forms should also be restricted.</p>
     *
     * @return rule allowing ASCII alphanumeric characters and ordinary spaces
     */
    public static ValidationRule<String> alphanumericWithSpace() {
        return new ValidationRule<String>(
                value -> value.matches("[A-Za-z0-9 ]+"),
                "must contain only alphanumeric characters and spaces");
    }

    /**
     * Requires an integer to be greater than zero.
     *
     * @return positive-integer validation rule
     */
    public static ValidationRule<Integer> positiveInteger() {
        return new ValidationRule<Integer>(
                value -> value > 0,
                "must be greater than zero");
    }

    /**
     * Requires an integer to fall within an inclusive range.
     *
     * @param minimum smallest valid value
     * @param maximum largest valid value
     * @return inclusive-range validation rule
     * @throws IllegalArgumentException when minimum is greater than maximum
     */
    public static ValidationRule<Integer> integerRange(final int minimum, final int maximum) {
        if (minimum > maximum) {
            throw new IllegalArgumentException(
                    "Minimum value must not be greater than maximum value");
        }

        return new ValidationRule<Integer>(
                value -> value >= minimum && value <= maximum,
                "must be between " + minimum + " and " + maximum);
    }

    /**
     * Requires a value to exactly match one member of a configured whitelist.
     *
     * <p>This rule is useful for SQL parameters representing a finite set of
     * values such as status, request type, operation type, category, or mode.
     * Matching uses the normal {@link Object#equals(Object)} contract, so String
     * comparisons performed by this generic rule are case-sensitive.</p>
     *
     * <p>Nullability should be expressed with {@link SqlParameter#nullable}
     * rather than by adding {@code null} to the allowed-values list.</p>
     *
     * @param allowedValues values that are permitted for the parameter
     * @param <T> Java type being validated
     * @return validation rule that accepts only one of the configured values
     * @throws IllegalArgumentException when the allowed-values array is null,
     *                                  empty, or contains a null element
     */
    @SafeVarargs
    public static <T> ValidationRule<T> allowedValues(final T... allowedValues) {
        validateAllowedValues(allowedValues);

        // Use a defensive copy so later changes to the caller's array do not
        // silently change the behavior of an already-created validation rule.
        final T[] values = Arrays.copyOf(allowedValues, allowedValues.length);

        return new ValidationRule<T>(
                value -> Arrays.asList(values).contains(value),
                "must be one of " + Arrays.toString(values));
    }

    /**
     * Requires a String to match one member of a configured whitelist while
     * ignoring character case.
     *
     * <p>For example, when {@code ACTIVE} is allowed, values such as
     * {@code active} and {@code Active} are also accepted. Use
     * {@link #allowedValues(Object[])} when the database/application contract is
     * intentionally case-sensitive.</p>
     *
     * @param allowedValues String values that are permitted for the parameter
     * @return case-insensitive allowed-values validation rule
     * @throws IllegalArgumentException when the allowed-values array is null,
     *                                  empty, or contains a null element
     */
    public static ValidationRule<String> allowedValuesIgnoreCase(
            final String... allowedValues) {
        validateAllowedValues(allowedValues);

        final String[] values = Arrays.copyOf(allowedValues, allowedValues.length);

        return new ValidationRule<String>(
                value -> {
                    for (String allowedValue : values) {
                        if (allowedValue.equalsIgnoreCase(value)) {
                            return true;
                        }
                    }
                    return false;
                },
                "must be one of " + Arrays.toString(values) + " (case-insensitive)");
    }

    /**
     * Validates configuration shared by the allowed-values factory methods.
     * Null parameter values themselves are handled by {@link SqlParameter};
     * this method only validates the whitelist definition.
     */
    private static <T> void validateAllowedValues(final T[] allowedValues) {
        if (allowedValues == null || allowedValues.length == 0) {
            throw new IllegalArgumentException(
                    "Allowed values must not be null or empty");
        }

        for (T allowedValue : allowedValues) {
            if (allowedValue == null) {
                throw new IllegalArgumentException(
                        "Allowed values must not contain null");
            }
        }
    }
}
