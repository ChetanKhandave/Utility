package com.chetankhandave.utility.json;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests immutable configuration behavior, normalization and builder validation.
 */
public class JsonMaskingConfigTest {

    /** Verifies the default configuration is a single reusable immutable instance. */
    @Test
    public void defaultConfig_returnsSameInstance() {
        assertSame(JsonMaskingConfig.defaultConfig(), JsonMaskingConfig.defaultConfig());
    }

    /** Verifies default rules contain representative policies from each masking category. */
    @Test
    public void defaultConfig_containsExpectedPolicies() {
        JsonMaskingConfig config = JsonMaskingConfig.defaultConfig();

        assertEquals(MaskingType.COMPLETE, config.getPolicy("password").getMaskingType());
        assertEquals(MaskingType.ALTERNATE, config.getPolicy("name").getMaskingType());
        assertEquals(MaskingType.KEEP_LAST_N, config.getPolicy("mobile").getMaskingType());
        assertEquals(4, config.getPolicy("mobile").getVisibleCharacters());
        assertEquals(MaskingType.KEEP_FIRST_N, config.getPolicy("email").getMaskingType());
        assertEquals(3, config.getPolicy("email").getVisibleCharacters());
    }

    /** Verifies key lookup is case-insensitive and trims surrounding whitespace. */
    @Test
    public void getPolicy_normalizesFieldName() {
        JsonMaskingConfig config = JsonMaskingConfig.defaultConfig();

        assertEquals(MaskingType.COMPLETE, config.getPolicy(" PASSWORD ").getMaskingType());
        assertEquals(MaskingType.KEEP_LAST_N, config.getPolicy("Mobile").getMaskingType());
    }

    /** Verifies null and unknown field names result in NONE policy. */
    @Test
    public void getPolicy_unknownOrNullKey_returnsNone() {
        JsonMaskingConfig config = JsonMaskingConfig.defaultConfig();

        assertEquals(MaskingType.NONE, config.getPolicy("unknown").getMaskingType());
        assertEquals(MaskingType.NONE, config.getPolicy(null).getMaskingType());
    }

    /** Verifies callers cannot mutate a built configuration map. */
    @Test
    public void getPolicies_returnsUnmodifiableMap() {
        final Map<String, MaskingPolicy> policies = JsonMaskingConfig.defaultConfig().getPolicies();

        assertThrows(UnsupportedOperationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() {
                policies.put("newkey", MaskingPolicy.complete());
            }
        });
    }

    /** Verifies blank and null configuration keys are rejected early. */
    @Test
    public void builder_rejectsBlankAndNullKeys() {
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() {
                JsonMaskingConfig.builder().completeMask("   ");
            }
        });

        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() {
                JsonMaskingConfig.builder().completeMask(null);
            }
        });
    }

    /** Verifies negative visible-character counts are rejected. */
    @Test
    public void builder_rejectsNegativeVisibleCharacterCount() {
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() {
                JsonMaskingConfig.builder().keepLast("mobile", -1);
            }
        });
    }

    /** Verifies custom configurations are independent of the default configuration. */
    @Test
    public void customConfig_doesNotModifyDefaultConfig() {
        JsonMaskingConfig custom = JsonMaskingConfig.builder().completeMask("city").build();

        assertEquals(MaskingType.COMPLETE, custom.getPolicy("city").getMaskingType());
        assertEquals(MaskingType.NONE, JsonMaskingConfig.defaultConfig().getPolicy("city").getMaskingType());
    }
}
