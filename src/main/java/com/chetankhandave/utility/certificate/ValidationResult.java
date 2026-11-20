package com.chetankhandave.utility.certificate;

import java.util.*;

/** Immutable outcomes for one validator; precedence is ERROR, FAIL, required NOT_CHECKED, PASS. */
public final class ValidationResult {
    private final String name;
    private final List<ValidationFinding> findings;
    public ValidationResult(String name,List<ValidationFinding> findings) {
        this.name=Objects.requireNonNull(name,"name");
        List<ValidationFinding> copy=new ArrayList<>(findings);
        for(ValidationFinding finding:copy) Objects.requireNonNull(finding,"finding");
        this.findings=Collections.unmodifiableList(copy);
    }
    public String getName() { return name; }
    public List<ValidationFinding> getFindings() { return findings; }
    public ValidationStatus getStatus() {
        if(findings.isEmpty()) return ValidationStatus.NOT_CHECKED;
        boolean fail=false,unchecked=false,pass=false;
        for(ValidationFinding finding:findings) {
            if(finding.getStatus()==ValidationStatus.ERROR) return ValidationStatus.ERROR;
            fail|=finding.getStatus()==ValidationStatus.FAIL;
            unchecked|=finding.isRequired() && finding.getStatus()==ValidationStatus.NOT_CHECKED;
            pass|=finding.getStatus()==ValidationStatus.PASS;
        }
        return fail?ValidationStatus.FAIL:unchecked || !pass?ValidationStatus.NOT_CHECKED:ValidationStatus.PASS;
    }
}
