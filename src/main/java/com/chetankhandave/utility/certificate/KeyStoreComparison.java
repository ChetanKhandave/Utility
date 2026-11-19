package com.chetankhandave.utility.certificate;

import java.util.*;

/** Immutable comparison data; formatting is delegated to a separate adapter. */
public final class KeyStoreComparison {
    public enum Status { ADDED, REMOVED, CHANGED, METADATA_CHANGED, UNCHANGED, NOT_COMPARABLE }
    public static final class Difference {
        private final String field, before, after;
        Difference(String field, String before, String after) {
            this.field=field; this.before=before; this.after=after;
        }
        public String getField() { return field; }
        public String getBefore() { return before; }
        public String getAfter() { return after; }
    }
    public static final class Entry {
        private final String alias;
        private final Status status;
        private final List<Difference> differences;
        private final List<AnalysisReport> before, after;
        Entry(String alias, Status status, List<Difference> differences,
                List<AnalysisReport> before, List<AnalysisReport> after) {
            this.alias=alias; this.status=status;
            this.differences=Collections.unmodifiableList(new ArrayList<>(differences));
            this.before=Collections.unmodifiableList(new ArrayList<>(before));
            this.after=Collections.unmodifiableList(new ArrayList<>(after));
        }
        public String getAlias() { return alias; }
        public Status getStatus() { return status; }
        public List<Difference> getDifferences() { return differences; }
        /** Entry metadata followed by certificate reports in stored chain order. */
        public List<AnalysisReport> getBefore() { return before; }
        public List<AnalysisReport> getAfter() { return after; }
    }
    private final List<Entry> entries;
    private final List<String> certificateRelocations;
    KeyStoreComparison(List<Entry> entries, List<String> relocations) {
        this.entries=Collections.unmodifiableList(new ArrayList<>(entries));
        this.certificateRelocations=Collections.unmodifiableList(new ArrayList<>(relocations));
    }
    public List<Entry> getEntries() { return entries; }
    /** Exact certificate occurrences across different aliases; not proof of a rename. */
    public List<String> getCertificateRelocations() { return certificateRelocations; }
    public Map<Status,Integer> getCounts() {
        Map<Status,Integer> counts=new EnumMap<>(Status.class);
        for(Status status:Status.values()) counts.put(status,0);
        for(Entry entry:entries) counts.put(entry.status,counts.get(entry.status)+1);
        return Collections.unmodifiableMap(counts);
    }
}
