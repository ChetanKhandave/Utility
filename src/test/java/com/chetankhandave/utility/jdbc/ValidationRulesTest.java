package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the reusable rules exposed by {@link ValidationRules}.
 *
 * <p>The suite focuses on normal values, exact boundaries, and invalid rule
 * configuration so callers can rely on predictable behavior before JDBC
 * binding occurs.</p>
 */
class ValidationRulesTest {

    /** Verifies that notBlank accepts ordinary non-whitespace text. */
    @Test
    void notBlankShouldAcceptNonBlankValue() {
        assertTrue(ValidationRules.notBlank().isValid("ABC"));
    }

    /** Verifies that notBlank rejects the empty string. */
    @Test
    void notBlankShouldRejectEmptyValue() {
        assertFalse(ValidationRules.notBlank().isValid(""));
    }

    /** Verifies that notBlank rejects strings containing only whitespace. */
    @Test
    void notBlankShouldRejectWhitespaceOnlyValue() {
        assertFalse(ValidationRules.notBlank().isValid("   "));
    }

    /** Verifies that maxLength accepts values shorter than the configured limit. */
    @Test
    void maxLengthShouldAcceptValueShorterThanLimit() {
        assertTrue(ValidationRules.maxLength(5).isValid("ABCD"));
    }

    /** Covers the exact maximum-length boundary, which must remain valid. */
    @Test
    void maxLengthShouldAcceptValueExactlyAtLimit() {
        assertTrue(ValidationRules.maxLength(5).isValid("ABCDE"));
    }

    /** Verifies rejection immediately above the maximum-length boundary. */
    @Test
    void maxLengthShouldRejectValueLongerThanLimit() {
        assertFalse(ValidationRules.maxLength(5).isValid("ABCDEF"));
    }

    /** Covers a zero-length maximum where only the empty string is valid. */
    @Test
    void maxLengthShouldAllowEmptyStringWhenMaximumIsZero() {
        assertTrue(ValidationRules.maxLength(0).isValid(""));
    }

    /** Verifies that a negative maximum cannot be used to construct a rule. */
    @Test
    void maxLengthShouldRejectNegativeMaximum() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.maxLength(-1));
    }

    /** Verifies that positiveInteger accepts the smallest positive value. */
    @Test
    void positiveIntegerShouldAcceptPositiveValue() {
        assertTrue(ValidationRules.positiveInteger().isValid(1));
    }

    /** Covers zero, which is not considered positive. */
    @Test
    void positiveIntegerShouldRejectZero() {
        assertFalse(ValidationRules.positiveInteger().isValid(0));
    }

    /** Verifies that negative integers are rejected by positiveInteger. */
    @Test
    void positiveIntegerShouldRejectNegativeValue() {
        assertFalse(ValidationRules.positiveInteger().isValid(-1));
    }

    /** Covers the inclusive lower boundary of an integer range. */
    @Test
    void integerRangeShouldAcceptMinimumBoundary() {
        assertTrue(ValidationRules.integerRange(18, 100).isValid(18));
    }

    /** Covers the inclusive upper boundary of an integer range. */
    @Test
    void integerRangeShouldAcceptMaximumBoundary() {
        assertTrue(ValidationRules.integerRange(18, 100).isValid(100));
    }

    /** Verifies rejection immediately below the configured range. */
    @Test
    void integerRangeShouldRejectValueBelowMinimum() {
        assertFalse(ValidationRules.integerRange(18, 100).isValid(17));
    }

    /** Verifies rejection immediately above the configured range. */
    @Test
    void integerRangeShouldRejectValueAboveMaximum() {
        assertFalse(ValidationRules.integerRange(18, 100).isValid(101));
    }

    /** Verifies that an inverted range definition is rejected at construction time. */
    @Test
    void integerRangeShouldRejectInvalidBounds() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.integerRange(100, 18));
    }
}
