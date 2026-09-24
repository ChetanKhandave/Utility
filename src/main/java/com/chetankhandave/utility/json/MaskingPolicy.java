package com.chetankhandave.utility.json;

/**
 * Immutable value object describing how a JSON field should be masked.
 * <p>
 * For COMPLETE, ALTERNATE and NONE, visibleCharacters is ignored.
 * For KEEP_LAST_N and KEEP_FIRST_N, visibleCharacters defines how many
 * characters remain visible.
 */
public final class MaskingPolicy {

    private final MaskingType maskingType;
    private final int visibleCharacters;

    private MaskingPolicy(MaskingType maskingType, int visibleCharacters) {
        if (maskingType == null) {
            throw new IllegalArgumentException("maskingType must not be null");
        }
        if (visibleCharacters < 0) {
            throw new IllegalArgumentException("visibleCharacters must not be negative");
        }
        this.maskingType = maskingType;
        this.visibleCharacters = visibleCharacters;
    }

    public static MaskingPolicy complete() {
        return new MaskingPolicy(MaskingType.COMPLETE, 0);
    }

    public static MaskingPolicy alternate() {
        return new MaskingPolicy(MaskingType.ALTERNATE, 0);
    }

    public static MaskingPolicy keepLast(int visibleCharacters) {
        return new MaskingPolicy(MaskingType.KEEP_LAST_N, visibleCharacters);
    }

    public static MaskingPolicy keepFirst(int visibleCharacters) {
        return new MaskingPolicy(MaskingType.KEEP_FIRST_N, visibleCharacters);
    }

    public static MaskingPolicy none() {
        return new MaskingPolicy(MaskingType.NONE, 0);
    }

    public MaskingType getMaskingType() {
        return maskingType;
    }

    public int getVisibleCharacters() {
        return visibleCharacters;
    }
}
