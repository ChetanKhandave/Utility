package com.chetankhandave.utility.certificate;

import java.util.Objects;

/** Immutable rule outcome. Optional unchecked rules do not block an otherwise successful result. */
public final class ValidationFinding {
    private final String ruleId, message;
    private final ValidationStatus status;
    private final boolean required;
    public ValidationFinding(String ruleId, ValidationStatus status, String message, boolean required) {
        this.ruleId=Objects.requireNonNull(ruleId,"ruleId");
        this.status=Objects.requireNonNull(status,"status");
        this.message=Objects.requireNonNull(message,"message"); this.required=required;
    }
    public String getRuleId() { return ruleId; }
    public ValidationStatus getStatus() { return status; }
    public String getMessage() { return message; }
    public boolean isRequired() { return required; }
    static ValidationFinding test(String id,boolean passed,String message) {
        return new ValidationFinding(id,passed?ValidationStatus.PASS:ValidationStatus.FAIL,message,true);
    }
}
