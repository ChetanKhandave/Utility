package com.chetankhandave.utility.certificate;

import java.util.*;

/** Runs independent checks despite failures; unexpected exceptions are reported without secret messages. */
public final class ValidationCoordinator {
    public List<ValidationResult> run(List<? extends ValidationCheck> checks) {
        List<ValidationResult> results=new ArrayList<>();
        for(ValidationCheck check:checks) {
            Objects.requireNonNull(check,"check");
            try { results.add(Objects.requireNonNull(check.validate(),"result")); }
            catch(Exception e) {
                results.add(new ValidationResult(check.getName(),Arrays.asList(new ValidationFinding(
                    "execution",ValidationStatus.ERROR,"Validation could not execute: "+e.getClass().getSimpleName(),true))));
            }
        }
        return Collections.unmodifiableList(results);
    }
}
