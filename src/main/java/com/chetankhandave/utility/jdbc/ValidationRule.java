package com.chetankhandave.utility.jdbc;

import java.util.function.Predicate;

/**
 * Associates a validation {@link Predicate} with a human-readable error message.
 *
 * <p>The predicate should be deterministic, fast, and side-effect free. Rules
 * should validate the supplied value itself; database-dependent checks are
 * better kept in the service or DAO layer.</p>
 *
 * @param <T> type of value validated by this rule
 */
public final class ValidationRule<T> {

    private final Predicate<T> predicate;
    private final String message;

    /**
     * Creates a validation rule.
     *
     * @param predicate condition that returns {@code true} for a valid value
     * @param message message reported when the condition returns {@code false}
     * @throws IllegalArgumentException if predicate or message is invalid
     */
    public ValidationRule(Predicate<T> predicate, String message) {
        if (predicate == null) {
            throw new IllegalArgumentException("Validation predicate must not be null");
        }
        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Validation message must not be null or empty");
        }

        this.predicate = predicate;
        this.message = message;
    }

    /**
     * Tests whether the supplied value satisfies this rule.
     *
     * @param value value to validate
     * @return {@code true} when valid; otherwise {@code false}
     */
    public boolean isValid(T value) {
        return predicate.test(value);
    }

    /**
     * Returns the message describing this validation requirement.
     *
     * @return validation failure message
     */
    public String getMessage() {
        return message;
    }
}
