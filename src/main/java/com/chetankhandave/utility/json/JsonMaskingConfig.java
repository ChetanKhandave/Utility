package com.chetankhandave.utility.json;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Immutable configuration that maps JSON field names to masking policies.
 * <p>
 * Field matching is case-insensitive and trims surrounding whitespace.
 * The default configuration is created once and safely reused across threads.
 */
public final class JsonMaskingConfig {

    private static final JsonMaskingConfig DEFAULT_CONFIG = builder()
            .completeMask("password")
            .completeMask("pass")
            .completeMask("pwd")
            .completeMask("token")
            .completeMask("access_token")
            .completeMask("refresh_token")
            .completeMask("secret")
            .completeMask("client_secret")
            .completeMask("api_key")
            .completeMask("apikey")
            .completeMask("otp")
            .completeMask("pin")
            .completeMask("cvv")
            .completeMask("cvc")
            .alternateMask("name")
            .alternateMask("firstName")
            .alternateMask("lastName")
            .alternateMask("customerName")
            .keepLast("mobile", 4)
            .keepLast("mobileNumber", 4)
            .keepLast("phone", 4)
            .keepLast("phoneNumber", 4)
            .keepLast("accountNumber", 4)
            .keepLast("accountNo", 4)
            .keepLast("cardNumber", 4)
            .keepLast("aadhaar", 4)
            .keepLast("aadhar", 4)
            .keepLast("pan", 4)
            .keepFirst("email", 3)
            .keepFirst("userId", 3)
            .keepFirst("username", 3)
            .build();

    private final Map<String, MaskingPolicy> policies;

    private JsonMaskingConfig(Map<String, MaskingPolicy> policies) {
        this.policies = Collections.unmodifiableMap(new HashMap<String, MaskingPolicy>(policies));
    }

    /**
     * Returns the reusable immutable application-wide default configuration.
     */
    public static JsonMaskingConfig defaultConfig() {
        return DEFAULT_CONFIG;
    }

    /**
     * Returns the policy for a field, or NONE when the field is not configured.
     */
    public MaskingPolicy getPolicy(String key) {
        if (key == null) {
            return MaskingPolicy.none();
        }
        MaskingPolicy policy = policies.get(normalize(key));
        return policy == null ? MaskingPolicy.none() : policy;
    }

    /**
     * Returns an unmodifiable view of configured policies.
     */
    public Map<String, MaskingPolicy> getPolicies() {
        return policies;
    }

    /**
     * Creates a builder for a custom immutable configuration.
     */
    public static Builder builder() {
        return new Builder();
    }

    static String normalize(String key) {
        return key == null ? null : key.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Mutable builder used only during configuration construction.
     * Built JsonMaskingConfig instances are immutable.
     */
    public static final class Builder {

        private final Map<String, MaskingPolicy> policies = new HashMap<String, MaskingPolicy>();

        public Builder completeMask(String key) {
            putPolicy(key, MaskingPolicy.complete());
            return this;
        }

        public Builder alternateMask(String key) {
            putPolicy(key, MaskingPolicy.alternate());
            return this;
        }

        public Builder keepLast(String key, int visibleCharacters) {
            putPolicy(key, MaskingPolicy.keepLast(visibleCharacters));
            return this;
        }

        public Builder keepFirst(String key, int visibleCharacters) {
            putPolicy(key, MaskingPolicy.keepFirst(visibleCharacters));
            return this;
        }

        public JsonMaskingConfig build() {
            return new JsonMaskingConfig(policies);
        }

        private void putPolicy(String key, MaskingPolicy policy) {
            if (key == null || key.trim().isEmpty()) {
                throw new IllegalArgumentException("key must not be null or blank");
            }
            policies.put(normalize(key), policy);
        }
    }
}
