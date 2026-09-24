package com.chetankhandave.utility.json;

/**
 * Default stateless masking strategy supporting all built-in masking types.
 * <p>
 * This implementation is thread-safe because it contains no mutable state.
 */
public final class DefaultMaskingStrategy implements MaskingStrategy {

    private static final String COMPLETE_MASK = "****";

    @Override
    public String mask(String value, MaskingPolicy policy) {
        if (value == null) {
            return null;
        }
        if (policy == null || policy.getMaskingType() == MaskingType.NONE) {
            return value;
        }

        switch (policy.getMaskingType()) {
            case COMPLETE:
                return COMPLETE_MASK;
            case ALTERNATE:
                return maskAlternate(value);
            case KEEP_LAST_N:
                return maskExceptLastN(value, policy.getVisibleCharacters());
            case KEEP_FIRST_N:
                return maskExceptFirstN(value, policy.getVisibleCharacters());
            case NONE:
            default:
                return value;
        }
    }

    String maskAlternate(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder result = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            result.append(i % 2 == 1 ? '*' : value.charAt(i));
        }
        return result.toString();
    }

    String maskExceptLastN(String value, int visibleCharacters) {
        if (value == null) {
            return null;
        }
        if (visibleCharacters <= 0) {
            return repeat('*', value.length());
        }
        if (value.length() <= visibleCharacters) {
            return value;
        }
        int maskLength = value.length() - visibleCharacters;
        return repeat('*', maskLength) + value.substring(maskLength);
    }

    String maskExceptFirstN(String value, int visibleCharacters) {
        if (value == null) {
            return null;
        }
        if (visibleCharacters <= 0) {
            return repeat('*', value.length());
        }
        if (value.length() <= visibleCharacters) {
            return value;
        }
        return value.substring(0, visibleCharacters) + repeat('*', value.length() - visibleCharacters);
    }

    private String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(Math.max(0, count));
        for (int i = 0; i < count; i++) {
            result.append(value);
        }
        return result.toString();
    }
}
