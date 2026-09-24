package com.chetankhandave.utility.json;

/**
 * Identifies the masking algorithm to apply to a JSON field value.
 */
public enum MaskingType {
    COMPLETE,
    ALTERNATE,
    KEEP_LAST_N,
    KEEP_FIRST_N,
    NONE
}
