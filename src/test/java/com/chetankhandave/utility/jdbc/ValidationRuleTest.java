package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationRuleTest {

    @Test
    void shouldAcceptValueWhenPredicateReturnsTrue() {
        ValidationRule<String> rule = new ValidationRule<String>(
                value -> value.startsWith("REQ-"),
                "must start with REQ-");

        assertTrue(rule.isValid("REQ-123"));
    }

    @Test
    void shouldRejectValueWhenPredicateReturnsFalse() {
        ValidationRule<String> rule = new ValidationRule<String>(
                value -> value.startsWith("REQ-"),
                "must start with REQ-");

        assertFalse(rule.isValid("ABC-123"));
    }

    @Test
    void shouldReturnConfiguredMessage() {
        ValidationRule<Integer> rule = new ValidationRule<Integer>(
                value -> value > 0,
                "must be positive");

        assertEquals("must be positive", rule.getMessage());
    }

    @Test
    void shouldRejectNullPredicate() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(null, "message"));

        assertEquals("Validation predicate must not be null", exception.getMessage());
    }

    @Test
    void shouldRejectNullMessage() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(value -> true, null));

        assertEquals("Validation message must not be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectEmptyMessage() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(value -> true, ""));
    }

    @Test
    void shouldRejectWhitespaceOnlyMessage() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ValidationRule<String>(value -> true, "   "));
    }
}
