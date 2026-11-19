package com.chetankhandave.utility.certificate;

import java.util.*;

/** Standalone, offline HTML adapter. All data is escaped; there is no JavaScript or remote asset. */
public final class HtmlComparisonReportFormatter implements ComparisonReportFormatter {
    @Override public String format(KeyStoreComparison comparison) {
        Objects.requireNonNull(comparison,"comparison");
        StringBuilder out=new StringBuilder("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"UTF-8\" />");
        out.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />")
            .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\" />")
            .append("<title>Keystore comparison</title><style>")
            .append("body{font:16px system-ui,sans-serif;line-height:1.5;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#f4f7fb;color:#172b45}")
            .append("article,header,.locations{background:white;padding:1.25rem;margin:1rem 0;border:1px solid #cbd5e1;border-radius:8px}")
            .append("table{width:100%;border-collapse:collapse;margin:1rem 0;table-layout:fixed}th,td{padding:.6rem;border:1px solid #cbd5e1;text-align:left;vertical-align:top;overflow-wrap:anywhere;white-space:pre-wrap}")
            .append("th{background:#edf2f7}.summary{display:flex;flex-wrap:wrap;gap:1rem}.summary div{padding:.5rem}.summary dt{font-weight:bold}")
            .append(".CHANGED{border-left:6px solid #b45309}.ADDED{border-left:6px solid #15803d}.REMOVED{border-left:6px solid #b91c1c}")
            .append(".METADATA_CHANGED{border-left:6px solid #7e22ce}.NOT_COMPARABLE{border-left:6px solid #475569}")
            .append(".snapshots{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1rem}summary{cursor:pointer;font-weight:bold}")
            .append("#changes-only:checked ~ main article.UNCHANGED{display:none}.hint{color:#334155}h2{overflow-wrap:anywhere}")
            .append("@media(max-width:700px){.snapshots{grid-template-columns:1fr}}@media print{input,label{display:none}body{max-width:none;background:white}}")
            .append("</style></head><body><header><h1>Keystore comparison</h1>")
            .append("<p>Scope: public certificates, chains and entry metadata. Private/secret key material: <strong>NOT_CHECKED</strong>. Trust validation: <strong>NOT_PERFORMED</strong>.</p>")
            .append("<p>UNCHANGED refers to public contents only. Change status and validation findings are separate.</p><dl class=\"summary\">");
        for(Map.Entry<KeyStoreComparison.Status,Integer> count:comparison.getCounts().entrySet())
            out.append("<div><dt>").append(count.getKey().name()).append("</dt><dd>").append(count.getValue()).append("</dd></div>");
        out.append("</dl></header><input type=\"checkbox\" id=\"changes-only\" /><label for=\"changes-only\"> Hide unchanged entries</label>")
            .append("<p class=\"hint\">NOT_COMPARABLE entries remain visible because key contents were not checked. Expand details to review each side.</p><main>");
        if(comparison.getEntries().isEmpty()) out.append("<p>No entries in either keystore.</p>");
        for(KeyStoreComparison.Entry entry:comparison.getEntries()) {
            out.append("<article class=\"").append(entry.getStatus().name()).append("\"><h2>[").append(entry.getStatus().name()).append("] ")
                .append(escape(entry.getAlias())).append("</h2>");
            if(entry.getDifferences().isEmpty()) out.append("<p>No field differences recorded; see entry status and scope.</p>");
            else {
                out.append("<table><caption>Field differences</caption><thead><tr><th scope=\"col\">Field</th><th scope=\"col\">Before</th><th scope=\"col\">After</th></tr></thead><tbody>");
                for(KeyStoreComparison.Difference difference:entry.getDifferences()) {
                    out.append("<tr><th scope=\"row\">").append(escape(difference.getField())).append("</th><td>")
                        .append(escape(difference.getBefore())).append("</td><td>").append(escape(difference.getAfter())).append("</td></tr>");
                }
                out.append("</tbody></table>");
            }
            out.append("<div class=\"snapshots\">");
            snapshot(out,"Before",entry.getBefore()); snapshot(out,"After",entry.getAfter());
            out.append("</div></article>");
        }
        out.append("<section class=\"locations\"><h2>Certificate alias locations</h2><p>Possible rename/copy observations are not proof of a rename.</p><ul>");
        for(String location:comparison.getCertificateRelocations()) out.append("<li>").append(escape(location)).append("</li>");
        return out.append("</ul></section></main></body></html>\n").toString();
    }
    private static void snapshot(StringBuilder out,String label,List<AnalysisReport> reports) {
        out.append("<section><h3>").append(label).append("</h3>");
        if(reports.isEmpty()) out.append("<p>Entry absent</p>");
        for(int i=0;i<reports.size();i++) {
            out.append("<details><summary>").append(i==0?"Entry metadata":"Certificate ["+(i-1)+"]").append("</summary><table><tbody>");
            for(Map.Entry<String,String> detail:reports.get(i).getDetails().entrySet())
                out.append("<tr><th scope=\"row\">").append(escape(detail.getKey())).append("</th><td>").append(escape(detail.getValue())).append("</td></tr>");
            out.append("</tbody></table><h4>Validation findings</h4>");
            if(reports.get(i).getFindings().isEmpty()) out.append("<p>No local findings. This does not establish trust.</p>");
            else {
                out.append("<ul>"); for(String finding:reports.get(i).getFindings()) out.append("<li>").append(escape(finding)).append("</li>"); out.append("</ul>");
            }
            out.append("</details>");
        }
        out.append("</section>");
    }
    /** Data only enters HTML text nodes, never scripts, styles, URLs or attributes. */
    private static String escape(String text) {
        if(text==null) return "(absent)";
        StringBuilder out=new StringBuilder();
        for(int i=0;i<text.length();i++) {
            char c=text.charAt(i);
            switch(c) {
                case '&':out.append("&amp;");break; case '<':out.append("&lt;");break;
                case '>':out.append("&gt;");break; case '"':out.append("&quot;");break;
                case '\'':out.append("&#39;");break;
                default:
                    if(Character.isHighSurrogate(c) && i+1<text.length() && Character.isLowSurrogate(text.charAt(i+1))) {
                        out.append(c).append(text.charAt(++i));
                    } else if(Character.isSurrogate(c) || (Character.isISOControl(c) && c!='\n' && c!='\r' && c!='\t') || c=='\ufffe' || c=='\uffff')
                        out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}
