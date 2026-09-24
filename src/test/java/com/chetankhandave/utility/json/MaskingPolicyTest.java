package com.chetankhandave.utility.json;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests construction and validation of immutable masking policies.
 */
public class MaskingPolicyTest {

    /** Verifies factory methods create the expected policy types. */
    @Test
    public void factoryMethods_createExpectedTypes() {
        assertEquals(MaskingType.COMPLETE, MaskingPolicy.complete().getMaskingType());
        assertEquals(MaskingType.ALTERNATE, MaskingPolicy.alternate().getMaskingType());
        assertEquals(MaskingType.KEEP_LAST_N, MaskingPolicy.keepLast(4).getMaskingType());
        assertEquals(MaskingType.KEEP_FIRST_N, MaskingPolicy.keepFirst(3).getMaskingType());
        assertEquals(MaskingType.NONE, MaskingPolicy.none().getMaskingType());
    }

    /** Verifies the visible-character count is retained for partial masking policies. */
    @Test
    public void partialMaskPolicies_retainVisibleCharacterCount() {
        assertEquals(4, MaskingPolicy.keepLast(4).getVisibleCharacters());
        assertEquals(3, MaskingPolicy.keepFirst(3).getVisibleCharacters());
    }

    /** Verifies a zero visible-character count is allowed and means mask all characters. */
    @Test
    public void partialMaskPolicies_allowZeroVisibleCharacters() {
        assertEquals(0, MaskingPolicy.keepLast(0).getVisibleCharacters());
        assertEquals(0, MaskingPolicy.keepFirst(0).getVisibleCharacters());
    }

    /** Verifies invalid negative visible-character counts are rejected. */
    @Test
    public void partialMaskPolicies_rejectNegativeVisibleCharacters() {
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() {
                MaskingPolicy.keepLast(-1);
            }
        });
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() {
                MaskingPolicy.keepFirst(-1);
            }
        });
    }
}
