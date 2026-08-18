package com.chetankhandave.utility.jdbc;

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
}
