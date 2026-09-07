package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the reusable rules exposed by {@link ValidationRules}.
 *
 * <p>The suite focuses on normal values, exact boundaries, invalid rule
 * configuration, and whitelist-style validation so callers can rely on
 * predictable behavior before JDBC binding occurs.</p>
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

    /**
     * Verifies the normal whitelist scenario: a value exactly matching one of
     * the configured allowed String values must be accepted.
     */
    @Test
    void allowedValuesShouldAcceptConfiguredStringValue() {
        ValidationRule<String> rule = ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED");

        assertTrue(rule.isValid("ACTIVE"));
    }

    /**
     * Verifies that a value outside the configured whitelist is rejected.
     * This is the primary protection expected for enum-like SQL parameters.
     */
    @Test
    void allowedValuesShouldRejectUnconfiguredStringValue() {
        ValidationRule<String> rule = ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED");

        assertFalse(rule.isValid("PENDING"));
    }

    /**
     * Confirms that the generic allowed-values rule is intentionally
     * case-sensitive when used with Strings.
     */
    @Test
    void allowedValuesShouldBeCaseSensitiveForStrings() {
        ValidationRule<String> rule = ValidationRules.allowedValues("ACTIVE");

        assertFalse(rule.isValid("active"));
    }

    /**
     * Verifies that allowedValues is generic and can validate non-String SQL
     * parameter types such as integer codes.
     */
    @Test
    void allowedValuesShouldSupportIntegerValues() {
        ValidationRule<Integer> rule = ValidationRules.allowedValues(10, 20, 30);

        assertTrue(rule.isValid(20));
        assertFalse(rule.isValid(40));
    }

    /**
     * Verifies that the validation error message lists the configured whitelist,
     * making failures easier to diagnose in logs and test output.
     */
    @Test
    void allowedValuesShouldDescribePermittedValuesInMessage() {
        ValidationRule<String> rule = ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE");

        assertEquals("must be one of [ACTIVE, INACTIVE]", rule.getMessage());
    }

    /**
     * Invalid rule configuration must fail immediately when no whitelist is
     * supplied, rather than creating a rule that can never succeed.
     */
    @Test
    void allowedValuesShouldRejectEmptyConfiguration() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ValidationRules.allowedValues(new String[0]));
    }

    /** Verifies that a null whitelist array is rejected during rule creation. */
    @Test
    void allowedValuesShouldRejectNullConfiguration() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ValidationRules.allowedValues((String[]) null));
    }

    /**
     * Null should not be mixed into the whitelist. Nullable SQL parameters are
     * represented explicitly with SqlParameter.nullable instead.
     */
    @Test
    void allowedValuesShouldRejectNullElement() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ValidationRules.allowedValues("ACTIVE", null));
    }

    /**
     * Verifies that the rule keeps its own copy of the allowed values so a
     * caller cannot accidentally change validation behavior by mutating the
     * original array after rule creation.
     */
    @Test
    void allowedValuesShouldUseDefensiveCopy() {
        String[] values = {"ACTIVE", "INACTIVE"};
        ValidationRule<String> rule = ValidationRules.allowedValues(values);

        values[0] = "CHANGED";

        assertTrue(rule.isValid("ACTIVE"));
        assertFalse(rule.isValid("CHANGED"));
    }

    /**
     * Verifies that the case-insensitive rule accepts a value even when the
     * input uses different character casing from the configured whitelist.
     */
    @Test
    void allowedValuesIgnoreCaseShouldAcceptDifferentCase() {
        ValidationRule<String> rule = ValidationRules.allowedValuesIgnoreCase(
                "ACTIVE", "INACTIVE", "BLOCKED");

        assertTrue(rule.isValid("active"));
        assertTrue(rule.isValid("Active"));
        assertTrue(rule.isValid("ACTIVE"));
    }

    /**
     * Case-insensitive matching changes only character case behavior; values
     * outside the whitelist must still be rejected.
     */
    @Test
    void allowedValuesIgnoreCaseShouldRejectUnknownValue() {
        ValidationRule<String> rule = ValidationRules.allowedValuesIgnoreCase(
                "ACTIVE", "INACTIVE", "BLOCKED");

        assertFalse(rule.isValid("PENDING"));
    }

    /** Verifies configuration validation for an empty case-insensitive whitelist. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectEmptyConfiguration() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ValidationRules.allowedValuesIgnoreCase(new String[0]));
    }

    /** Verifies configuration validation for a null case-insensitive whitelist. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectNullConfiguration() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ValidationRules.allowedValuesIgnoreCase((String[]) null));
    }

    /** Verifies that null entries are not allowed in a case-insensitive whitelist. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectNullElement() {
        assertThrows(
                IllegalArgumentException.class,
                () -> ValidationRules.allowedValuesIgnoreCase("ACTIVE", null));
    }
}
