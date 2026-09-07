package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ValidationRule}.
 *
 * <p>These tests isolate the rule abstraction itself and verify predicate
 * evaluation plus constructor validation. No JDBC objects or database are
 * involved.</p>
 */
class ValidationRuleTest {

    /** Verifies that a value is accepted when its predicate evaluates to true. */
    @Test
    void shouldAcceptValueWhenPredicateReturnsTrue() {
        ValidationRule<String> rule = new ValidationRule<String>(
                value -> value.startsWith("REQ-"),
                "must start with REQ-");
        assertTrue(rule.isValid("REQ-123"));
    }

    /** Verifies that a value is rejected when its predicate evaluates to false. */
    @Test
    void shouldRejectValueWhenPredicateReturnsFalse() {
        ValidationRule<String> rule = new ValidationRule<String>(
                value -> value.startsWith("REQ-"),
                "must start with REQ-");
        assertFalse(rule.isValid("ABC-123"));
    }

    /** Verifies that the configured validation message is preserved unchanged. */
    @Test
    void shouldReturnConfiguredMessage() {
        ValidationRule<Integer> rule = new ValidationRule<Integer>(
                value -> value > 0,
                "must be positive");
        assertEquals("must be positive", rule.getMessage());
    }

    /** Covers the invalid-construction scenario where no predicate is supplied. */
    @Test
    void shouldRejectNullPredicate() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(null, "message"));
        assertEquals("Validation predicate must not be null", exception.getMessage());
    }

    /** Covers the invalid-construction scenario where the failure message is null. */
    @Test
    void shouldRejectNullMessage() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(value -> true, null));
        assertEquals("Validation message must not be null or empty", exception.getMessage());
    }

    /** Ensures an empty failure message is rejected because it would reduce diagnostics. */
    @Test
    void shouldRejectEmptyMessage() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(value -> true, ""));
    }

    /** Ensures a whitespace-only failure message is treated as invalid. */
    @Test
    void shouldRejectWhitespaceOnlyMessage() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(value -> true, "   "));
    }
}
