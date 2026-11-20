package com.chetankhandave.utility.certificate;

import java.util.*;

/** Human-readable formatter. Control characters are escaped to keep report lines intact. */
public final class TextComparisonReportFormatter implements ComparisonReportFormatter {
    @Override public String format(KeyStoreComparison comparison) {
        StringBuilder out=new StringBuilder("Keystore comparison\n");
        out.append("Scope: public certificates/chains and entry metadata. Private/secret key material: NOT_CHECKED.\n");
        out.append("UNCHANGED means public contents only. Presence/change does not establish trust.\n");
        for(Map.Entry<KeyStoreComparison.Status,Integer> count:comparison.getCounts().entrySet())
            out.append(count.getKey()).append(": ").append(count.getValue()).append('\n');
        for(KeyStoreComparison.Entry entry:comparison.getEntries()) {
            out.append("\n[").append(entry.getStatus()).append("] ").append(safe(entry.getAlias())).append('\n');
            for(KeyStoreComparison.Difference difference:entry.getDifferences()) {
                out.append("  ").append(safe(difference.getField())).append(":\n    Old: ")
                    .append(safe(difference.getBefore())).append("\n    New: ").append(safe(difference.getAfter())).append('\n');
            }
            appendReports(out,"Old",entry.getBefore()); appendReports(out,"New",entry.getAfter());
        }
        out.append("\nIdentical certificates with changed alias locations (possible rename/copy):\n");
        for(String location:comparison.getCertificateRelocations()) out.append("  ").append(safe(location)).append('\n');
        return out.toString();
    }
    private static void appendReports(StringBuilder out,String label,List<AnalysisReport> reports) {
        for(int i=0;i<reports.size();i++) {
            out.append("  ").append(label).append(i==0?" entry":" certificate["+(i-1)+"]").append(":\n");
            for(Map.Entry<String,String> detail:reports.get(i).getDetails().entrySet())
                out.append("    ").append(safe(detail.getKey())).append(" = ").append(safe(detail.getValue())).append('\n');
            for(String finding:reports.get(i).getFindings()) out.append("    Finding: ").append(safe(finding)).append('\n');
        }
    }
    static String safe(String value) {
        if(value==null) return "<absent>";
        StringBuilder escaped=new StringBuilder();
        for(char c:value.toCharArray()) {
            if(Character.isISOControl(c)) escaped.append(String.format(Locale.ROOT,"\\u%04x",(int)c));
            else escaped.append(c);
        }
        return escaped.toString();
    }
}
