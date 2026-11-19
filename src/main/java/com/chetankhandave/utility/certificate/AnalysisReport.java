package com.chetankhandave.utility.certificate;

import java.util.*;

/** Immutable report containing public metadata only. */
public final class AnalysisReport {
    private final Map<String, String> details;
    private final List<String> findings;
    public AnalysisReport(Map<String, String> details, List<String> findings) {
        this.details = Collections.unmodifiableMap(new LinkedHashMap<>(details));
        this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
    }
    public Map<String, String> getDetails() { return details; }
    public List<String> getFindings() { return findings; }
    @Override public String toString() { return details + System.lineSeparator() + findings; }
}
