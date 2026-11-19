package com.chetankhandave.utility.certificate;

/** Strategy for rendering immutable comparison data in different output formats. */
@FunctionalInterface
public interface ComparisonReportFormatter {
    String format(KeyStoreComparison comparison);
}
