package com.chetankhandave.utility.json;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the default scalar masking strategy.
 */
public class DefaultMaskingStrategyTest {

    private final DefaultMaskingStrategy strategy = new DefaultMaskingStrategy();

    /** Verifies complete masking of a non-null value. */
    @Test
    public void mask_completePolicy_returnsFixedMask() {
        assertEquals("****", strategy.mask("secret", MaskingPolicy.complete()));
    }

    /** Verifies null values remain null and are not converted to text. */
    @Test
    public void mask_nullValue_returnsNull() {
        assertNull(strategy.mask(null, MaskingPolicy.complete()));
    }

    /** Verifies a null policy leaves the original value unchanged. */
    @Test
    public void mask_nullPolicy_returnsOriginalValue() {
        assertEquals("value", strategy.mask("value", null));
    }

    /** Verifies NONE policy leaves the original value unchanged. */
    @Test
    public void mask_nonePolicy_returnsOriginalValue() {
        assertEquals("value", strategy.mask("value", MaskingPolicy.none()));
    }

    /** Verifies every second character is masked starting at index 1. */
    @Test
    public void mask_alternatePolicy_masksOddIndexes() {
        assertEquals("c*e*a*", strategy.mask("chetan", MaskingPolicy.alternate()));
        assertEquals("c*e*a", strategy.mask("cheta", MaskingPolicy.alternate()));
        assertEquals("9*7*5*3*1*", strategy.mask("9876543210", MaskingPolicy.alternate()));
    }

    /** Verifies alternate masking edge cases. */
    @Test
    public void maskAlternate_handlesEmptyAndSingleCharacterValues() {
        assertEquals("", strategy.maskAlternate(""));
        assertEquals("a", strategy.maskAlternate("a"));
        assertEquals("a*", strategy.maskAlternate("ab"));
        assertNull(strategy.maskAlternate(null));
    }

    /** Verifies KEEP_LAST_N masks all but the configured suffix. */
    @Test
    public void mask_keepLastPolicy_preservesConfiguredSuffix() {
        assertEquals("******3210", strategy.mask("9876543210", MaskingPolicy.keepLast(4)));
        assertEquals("********9012", strategy.mask("123456789012", MaskingPolicy.keepLast(4)));
    }

    /** Verifies KEEP_LAST_N boundary conditions. */
    @Test
    public void maskExceptLastN_handlesBoundaryConditions() {
        assertNull(strategy.maskExceptLastN(null, 4));
        assertEquals("123", strategy.maskExceptLastN("123", 4));
        assertEquals("*****", strategy.maskExceptLastN("12345", 0));
    }

    /** Verifies KEEP_FIRST_N masks all but the configured prefix. */
    @Test
    public void mask_keepFirstPolicy_preservesConfiguredPrefix() {
        assertEquals("che***", strategy.mask("chetan", MaskingPolicy.keepFirst(3)));
        assertEquals("use****", strategy.mask("user123", MaskingPolicy.keepFirst(3)));
    }

    /** Verifies KEEP_FIRST_N boundary conditions. */
    @Test
    public void maskExceptFirstN_handlesBoundaryConditions() {
        assertNull(strategy.maskExceptFirstN(null, 3));
        assertEquals("abc", strategy.maskExceptFirstN("abc", 5));
        assertEquals("*****", strategy.maskExceptFirstN("12345", 0));
    }
}
