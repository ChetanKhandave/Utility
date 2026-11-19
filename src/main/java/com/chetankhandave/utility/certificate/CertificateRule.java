package com.chetankhandave.utility.certificate;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/** Strategy: add local certificate policies without modifying the analyzer. */
@FunctionalInterface
public interface CertificateRule {
    void evaluate(X509Certificate certificate, Instant at, List<String> findings);
}
