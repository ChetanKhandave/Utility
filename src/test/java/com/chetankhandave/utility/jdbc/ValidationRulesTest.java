package com.chetankhandave.utility.jdbc;

import org.junit.jupiter.api.Test;

import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the reusable rules exposed by {@link ValidationRules}.
 *
 * <p>The suite focuses on normal values, exact boundaries, invalid rule
 * configuration, whitelist-style validation, strict String-format rules, and
 * direct null-safety. Every value-validation rule must return false for null
 * rather than throwing NullPointerException.</p>
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

    /** Verifies direct null validation is safe and returns false. */
    @Test
    void notBlankShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.notBlank().isValid(null));
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

    /** Verifies maxLength rejects null without dereferencing it. */
    @Test
    void maxLengthShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.maxLength(5).isValid(null));
    }

    /** Verifies that a negative maximum cannot be used to construct a rule. */
    @Test
    void maxLengthShouldRejectNegativeMaximum() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.maxLength(-1));
    }

    /** Verifies matchesPattern accepts a value matching the complete format. */
    @Test
    void matchesPatternShouldAcceptMatchingValue() {
        ValidationRule<String> rule = ValidationRules.matchesPattern("REQ-[0-9]{4}");
        assertTrue(rule.isValid("REQ-1001"));
    }

    /** Verifies matchesPattern rejects values outside the complete format. */
    @Test
    void matchesPatternShouldRejectNonMatchingValue() {
        ValidationRule<String> rule = ValidationRules.matchesPattern("REQ-[0-9]{4}");
        assertFalse(rule.isValid("ABC-1001"));
        assertFalse(rule.isValid("REQ-1001-EXTRA"));
    }

    /** Verifies matchesPattern rejects a null input without throwing. */
    @Test
    void matchesPatternShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.matchesPattern("REQ-[0-9]{4}").isValid(null));
    }

    /** Verifies that a null regular-expression definition is rejected immediately. */
    @Test
    void matchesPatternShouldRejectNullPattern() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.matchesPattern(null));
    }

    /** Verifies that a blank regular-expression definition is rejected immediately. */
    @Test
    void matchesPatternShouldRejectBlankPattern() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.matchesPattern("   "));
    }

    /** Verifies that an invalid regular expression surfaces PatternSyntaxException. */
    @Test
    void matchesPatternShouldRejectInvalidRegularExpression() {
        assertThrows(PatternSyntaxException.class,
                () -> ValidationRules.matchesPattern("[A-Z"));
    }

    /** Verifies that the rule message identifies the required regular expression. */
    @Test
    void matchesPatternShouldDescribeRequiredPatternInMessage() {
        ValidationRule<String> rule = ValidationRules.matchesPattern("REQ-[0-9]{4}");
        assertEquals("must match pattern REQ-[0-9]{4}", rule.getMessage());
    }

    /** Verifies that alphanumeric accepts mixed ASCII letters and digits. */
    @Test
    void alphanumericShouldAcceptLettersAndDigits() {
        assertTrue(ValidationRules.alphanumeric().isValid("Customer123"));
    }

    /** Verifies that alphanumeric also accepts a value containing only letters. */
    @Test
    void alphanumericShouldAcceptLettersOnly() {
        assertTrue(ValidationRules.alphanumeric().isValid("Customer"));
    }

    /** Verifies that alphanumeric also accepts a value containing only digits. */
    @Test
    void alphanumericShouldAcceptDigitsOnly() {
        assertTrue(ValidationRules.alphanumeric().isValid("12345"));
    }

    /** Verifies spaces and punctuation are rejected by the strict allow-list. */
    @Test
    void alphanumericShouldRejectSpaceAndPunctuation() {
        ValidationRule<String> rule = ValidationRules.alphanumeric();
        assertFalse(rule.isValid("Customer 123"));
        assertFalse(rule.isValid("Customer-123"));
        assertFalse(rule.isValid("Customer_123"));
    }

    /** Covers HTML-like characters outside the strict alphanumeric allow-list. */
    @Test
    void alphanumericShouldRejectHtmlLikeCharacters() {
        assertFalse(ValidationRules.alphanumeric().isValid("script>alert1"));
    }

    /** Verifies that alphanumeric requires at least one character. */
    @Test
    void alphanumericShouldRejectEmptyString() {
        assertFalse(ValidationRules.alphanumeric().isValid(""));
    }

    /** Verifies alphanumeric rejects null without throwing. */
    @Test
    void alphanumericShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.alphanumeric().isValid(null));
    }

    /** Verifies alphanumericWithSpace accepts normal words separated by spaces. */
    @Test
    void alphanumericWithSpaceShouldAcceptLettersDigitsAndSpaces() {
        assertTrue(ValidationRules.alphanumericWithSpace().isValid("Customer 123 India"));
    }

    /** Documents that ordinary leading, trailing, and repeated spaces are permitted. */
    @Test
    void alphanumericWithSpaceShouldAllowOrdinaryRepeatedSpaces() {
        ValidationRule<String> rule = ValidationRules.alphanumericWithSpace();
        assertTrue(rule.isValid(" Customer  123 "));
    }

    /** Verifies that tabs and line breaks are not treated as allowed spaces. */
    @Test
    void alphanumericWithSpaceShouldRejectTabsAndLineBreaks() {
        ValidationRule<String> rule = ValidationRules.alphanumericWithSpace();
        assertFalse(rule.isValid("Customer\t123"));
        assertFalse(rule.isValid("Customer\n123"));
    }

    /** Verifies punctuation and HTML-related characters are rejected. */
    @Test
    void alphanumericWithSpaceShouldRejectPunctuationAndHtmlLikeCharacters() {
        ValidationRule<String> rule = ValidationRules.alphanumericWithSpace();
        assertFalse(rule.isValid("Customer & Company"));
        assertFalse(rule.isValid("<script>alert1</script>"));
    }

    /** Verifies that alphanumericWithSpace requires at least one character. */
    @Test
    void alphanumericWithSpaceShouldRejectEmptyString() {
        assertFalse(ValidationRules.alphanumericWithSpace().isValid(""));
    }

    /** Verifies alphanumericWithSpace rejects null without throwing. */
    @Test
    void alphanumericWithSpaceShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.alphanumericWithSpace().isValid(null));
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

    /** Verifies positiveInteger rejects null without unboxing it. */
    @Test
    void positiveIntegerShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.positiveInteger().isValid(null));
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

    /** Verifies integerRange rejects null without unboxing it. */
    @Test
    void integerRangeShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.integerRange(18, 100).isValid(null));
    }

    /** Verifies that an inverted range definition is rejected at construction time. */
    @Test
    void integerRangeShouldRejectInvalidBounds() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.integerRange(100, 18));
    }

    /** Verifies the normal whitelist scenario for a configured String value. */
    @Test
    void allowedValuesShouldAcceptConfiguredStringValue() {
        ValidationRule<String> rule = ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED");
        assertTrue(rule.isValid("ACTIVE"));
    }

    /** Verifies that a value outside the configured whitelist is rejected. */
    @Test
    void allowedValuesShouldRejectUnconfiguredStringValue() {
        ValidationRule<String> rule = ValidationRules.allowedValues(
                "ACTIVE", "INACTIVE", "BLOCKED");
        assertFalse(rule.isValid("PENDING"));
    }

    /** Verifies allowedValues rejects null directly and safely. */
    @Test
    void allowedValuesShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.allowedValues("ACTIVE", "INACTIVE").isValid(null));
    }

    /** Confirms that the generic allowed-values rule is case-sensitive for Strings. */
    @Test
    void allowedValuesShouldBeCaseSensitiveForStrings() {
        ValidationRule<String> rule = ValidationRules.allowedValues("ACTIVE");
        assertFalse(rule.isValid("active"));
    }

    /** Verifies that allowedValues can validate non-String SQL parameter types. */
    @Test
    void allowedValuesShouldSupportIntegerValues() {
        ValidationRule<Integer> rule = ValidationRules.allowedValues(10, 20, 30);
        assertTrue(rule.isValid(20));
        assertFalse(rule.isValid(40));
    }

    /** Verifies that the validation message lists the configured whitelist. */
    @Test
    void allowedValuesShouldDescribePermittedValuesInMessage() {
        ValidationRule<String> rule = ValidationRules.allowedValues("ACTIVE", "INACTIVE");
        assertEquals("must be one of [ACTIVE, INACTIVE]", rule.getMessage());
    }

    /** Invalid rule configuration must fail immediately when no whitelist is supplied. */
    @Test
    void allowedValuesShouldRejectEmptyConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.allowedValues(new String[0]));
    }

    /** Verifies that a null whitelist array is rejected during rule creation. */
    @Test
    void allowedValuesShouldRejectNullConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.allowedValues((String[]) null));
    }

    /** Verifies null is not allowed as an allowed-value element. */
    @Test
    void allowedValuesShouldRejectNullElement() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.allowedValues("ACTIVE", null));
    }

    /** Verifies that mutating the caller's array does not mutate the rule. */
    @Test
    void allowedValuesShouldUseDefensiveCopy() {
        String[] values = {"ACTIVE", "INACTIVE"};
        ValidationRule<String> rule = ValidationRules.allowedValues(values);
        values[0] = "CHANGED";
        assertTrue(rule.isValid("ACTIVE"));
        assertFalse(rule.isValid("CHANGED"));
    }

    /** Verifies case-insensitive acceptance of differently cased allowed values. */
    @Test
    void allowedValuesIgnoreCaseShouldAcceptDifferentCase() {
        ValidationRule<String> rule = ValidationRules.allowedValuesIgnoreCase(
                "ACTIVE", "INACTIVE", "BLOCKED");
        assertTrue(rule.isValid("active"));
        assertTrue(rule.isValid("Active"));
        assertTrue(rule.isValid("ACTIVE"));
    }

    /** Verifies that unknown values remain invalid during case-insensitive matching. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectUnknownValue() {
        ValidationRule<String> rule = ValidationRules.allowedValuesIgnoreCase(
                "ACTIVE", "INACTIVE", "BLOCKED");
        assertFalse(rule.isValid("PENDING"));
    }

    /** Verifies allowedValuesIgnoreCase rejects null directly and safely. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectNullWithoutThrowing() {
        assertFalse(ValidationRules.allowedValuesIgnoreCase("ACTIVE", "INACTIVE").isValid(null));
    }

    /** Verifies configuration validation for an empty case-insensitive whitelist. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectEmptyConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.allowedValuesIgnoreCase(new String[0]));
    }

    /** Verifies configuration validation for a null case-insensitive whitelist. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectNullConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.allowedValuesIgnoreCase((String[]) null));
    }

    /** Verifies that null entries are not allowed in a case-insensitive whitelist. */
    @Test
    void allowedValuesIgnoreCaseShouldRejectNullElement() {
        assertThrows(IllegalArgumentException.class,
                () -> ValidationRules.allowedValuesIgnoreCase("ACTIVE", null));
    }
}
