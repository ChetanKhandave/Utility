package com.chetankhandave.utility.certificate;

import java.util.*;

/** Aggregate comparison and independent validation outcomes for a single deployment review. */
public final class DeploymentValidationReport {
    private final KeyStoreComparison comparison;
    private final List<ValidationResult> results;
    public DeploymentValidationReport(KeyStoreComparison comparison,List<ValidationResult> results) {
        this.comparison=Objects.requireNonNull(comparison,"comparison");
        List<ValidationResult> copy=new ArrayList<>(results);for(ValidationResult result:copy) Objects.requireNonNull(result,"result");
        this.results=Collections.unmodifiableList(copy);
    }
    public KeyStoreComparison getComparison() { return comparison; }
    public List<ValidationResult> getResults() { return results; }
    public ValidationStatus getStatus() {
        List<ValidationFinding> f=new ArrayList<>();
        for(ValidationResult result:results) f.add(new ValidationFinding(result.getName(),result.getStatus(),result.getName(),true));
        return new ValidationResult("overall",f).getStatus();
    }
}
