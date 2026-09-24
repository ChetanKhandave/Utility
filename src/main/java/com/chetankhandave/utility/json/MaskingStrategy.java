package com.chetankhandave.utility.json;

/**
 * Strategy contract for masking a scalar value.
 * Implementations must be stateless so they can be safely reused across threads.
 */
public interface MaskingStrategy {

    /**
     * Applies masking to the supplied value according to the supplied policy.
     *
     * @param value  scalar value to mask; may be null
     * @param policy masking policy; never null when invoked by JsonMasker
     * @return masked value, or null when input value is null
     */
    String mask(String value, MaskingPolicy policy);
}
