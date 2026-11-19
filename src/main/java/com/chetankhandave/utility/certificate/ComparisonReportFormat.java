package com.chetankhandave.utility.certificate;

import java.util.Locale;
import java.util.Objects;

/** Small factory selects a formatter strategy; comparison logic is format independent. */
public enum ComparisonReportFormat {
    TEXT, JSON, HTML;
    public ComparisonReportFormatter formatter() {
        switch(this) {
            case JSON:return new JsonComparisonReportFormatter();
            case HTML:return new HtmlComparisonReportFormatter();
            default:return new TextComparisonReportFormatter();
        }
    }
    public static ComparisonReportFormat parse(String value) {
        return valueOf(Objects.requireNonNull(value,"format").toUpperCase(Locale.ROOT));
    }
}
