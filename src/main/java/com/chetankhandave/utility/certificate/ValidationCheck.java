package com.chetankhandave.utility.certificate;

/** Strategy for independent validation. Implementations must not modify stores or input certificates. */
public interface ValidationCheck {
    String getName();
    ValidationResult validate() throws Exception;
}
