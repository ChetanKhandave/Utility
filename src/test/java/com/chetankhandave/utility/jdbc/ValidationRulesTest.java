package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationRulesTest {

    @Test
    void notBlankShouldAcceptNonBlankValue() {
        assertTrue(ValidationRules.notBlank().isValid("ABC"));
    }

    @Test
    void notBlankShouldRejectEmptyValue() {
        assertFalse(ValidationRules.notBlank().isValid(""));
    }

    @Test
    void notBlankShouldRejectWhitespaceOnlyValue() {
        assertFalse(ValidationRules.notBlank().isValid("   "));
    }

    @Test
    void maxLengthShouldAcceptValueShorterThanLimit() {
        assertTrue(ValidationRules.maxLength(5).isValid("ABCD"));
    }

    @Test
    void maxLengthShouldAcceptValueExactlyAtLimit() {
        assertTrue(ValidationRules.maxLength(5).isValid("ABCDE"));
    }

    @Test
    void maxLengthShouldRejectValueLongerThanLimit() {
        assertFalse(ValidationRules.maxLength(5).isValid("ABCDEF"));
    }

    @Test
    void maxLengthShouldAllowEmptyStringWhenMaximumIsZero() {
        assertTrue(ValidationRules.maxLength(0).isValid(""));
    }

    @Test
    void maxLengthShouldRejectNegativeMaximum() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.maxLength(-1));
    }

    @Test
    void positiveIntegerShouldAcceptPositiveValue() {
        assertTrue(ValidationRules.positiveInteger().isValid(1));
    }

    @Test
    void positiveIntegerShouldRejectZero() {
        assertFalse(ValidationRules.positiveInteger().isValid(0));
    }

    @Test
    void positiveIntegerShouldRejectNegativeValue() {
        assertFalse(ValidationRules.positiveInteger().isValid(-1));
    }

    @Test
    void integerRangeShouldAcceptMinimumBoundary() {
        assertTrue(ValidationRules.integerRange(18, 100).isValid(18));
    }

    @Test
    void integerRangeShouldAcceptMaximumBoundary() {
        assertTrue(ValidationRules.integerRange(18, 100).isValid(100));
    }

    @Test
    void integerRangeShouldRejectValueBelowMinimum() {
        assertFalse(ValidationRules.integerRange(18, 100).isValid(17));
    }

    @Test
    void integerRangeShouldRejectValueAboveMaximum() {
        assertFalse(ValidationRules.integerRange(18, 100).isValid(101));
    }

    @Test
    void integerRangeShouldRejectInvalidBounds() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.integerRange(100, 18));
    }
}
