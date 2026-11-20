package com.chetankhandave.utility.certificate;

import java.util.*;

/** Evaluates actual comparator statuses; certificate change and metadata change are separate permissions. */
public final class ExpectedChangeValidator implements ValidationCheck {
    private final KeyStoreComparison comparison;
    private final ExpectedChangePolicy policy;
    public ExpectedChangeValidator(KeyStoreComparison comparison,ExpectedChangePolicy policy) {
        this.comparison=Objects.requireNonNull(comparison,"comparison");this.policy=Objects.requireNonNull(policy,"policy");
    }
    @Override public String getName() { return "expected-changes"; }
    @Override public ValidationResult validate() {
        List<ValidationFinding> findings=new ArrayList<>(); Map<String,KeyStoreComparison.Entry> entries=new TreeMap<>();
        for(KeyStoreComparison.Entry entry:comparison.getEntries()) {
            entries.put(entry.getAlias(),entry);
            KeyStoreComparison.Status status=entry.getStatus();
            if(status==KeyStoreComparison.Status.NOT_COMPARABLE)
                findings.add(new ValidationFinding("change."+entry.getAlias(),ValidationStatus.NOT_CHECKED,"Secret-key contents cannot be compared",true));
            else if(status!=KeyStoreComparison.Status.UNCHANGED) {
                boolean permitted=policy.allowed.containsKey(entry.getAlias()) && policy.allowed.get(entry.getAlias()).contains(status);
                findings.add(ValidationFinding.test("change."+entry.getAlias(),permitted,"Observed "+status+" for alias "+entry.getAlias()+(permitted?" is approved":" is not approved")));
            }
        }
        for(Map.Entry<String,Set<KeyStoreComparison.Status>> requirement:policy.required.entrySet()) {
            KeyStoreComparison.Entry entry=entries.get(requirement.getKey());
            findings.add(ValidationFinding.test("required-change."+requirement.getKey(),entry!=null && requirement.getValue().contains(entry.getStatus()),
                "Required change for "+requirement.getKey()+": "+requirement.getValue()));
        }
        for(String alias:policy.requiredAliases) {
            KeyStoreComparison.Entry entry=entries.get(alias);
            findings.add(ValidationFinding.test("required-alias."+alias,entry!=null && entry.getStatus()!=KeyStoreComparison.Status.REMOVED,"Required new-store alias: "+alias));
        }
        if(findings.isEmpty()) findings.add(ValidationFinding.test("changes",true,"No unapproved public changes observed"));
        return new ValidationResult(getName(),findings);
    }
}
