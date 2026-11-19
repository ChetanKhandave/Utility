package com.chetankhandave.utility.certificate;

import java.time.Instant;

/** Immutable location and public certificate details of one exact match. */
public final class CertificateMatch {
    private final String alias;
    private final String entryType;
    private final Instant creationTime;
    private final int chainIndex;
    private final AnalysisReport certificateReport;

    CertificateMatch(String alias, String entryType, Instant creationTime,
            int chainIndex, AnalysisReport certificateReport) {
        this.alias = alias;
        this.entryType = entryType;
        this.creationTime = creationTime;
        this.chainIndex = chainIndex;
        this.certificateReport = certificateReport;
    }
    public String getAlias() { return alias; }
    public String getEntryType() { return entryType; }
    /** Store entry creation time, not the certificate's issue date; may be null. */
    public Instant getCreationTime() { return creationTime; }
    /** Zero-based chain position, or -1 for a standalone trusted certificate. */
    public int getChainIndex() { return chainIndex; }
    public AnalysisReport getCertificateReport() { return certificateReport; }
    @Override public String toString() {
        return "alias=" + alias + ", entryType=" + entryType + ", created=" + creationTime
            + ", chainIndex=" + chainIndex + System.lineSeparator() + certificateReport;
    }
}
