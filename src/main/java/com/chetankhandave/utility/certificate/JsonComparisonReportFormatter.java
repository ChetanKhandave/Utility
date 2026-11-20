package com.chetankhandave.utility.certificate;

import java.util.*;

/** JSON adapter with a versioned schema and no runtime dependencies. */
public final class JsonComparisonReportFormatter implements ComparisonReportFormatter {
    @Override public String format(KeyStoreComparison comparison) {
        Objects.requireNonNull(comparison,"comparison");
        Map<String,Object> document=new LinkedHashMap<>();
        document.put("schemaVersion","1.0");
        document.put("summary",comparison.getCounts());
        Map<String,String> scope=new LinkedHashMap<>();
        scope.put("privateKeyMaterial","NOT_CHECKED");
        scope.put("secretKeyMaterial","NOT_CHECKED");
        scope.put("trustValidation","NOT_PERFORMED");
        document.put("scope",scope);
        List<Object> entries=new ArrayList<>();
        for(KeyStoreComparison.Entry entry:comparison.getEntries()) {
            Map<String,Object> item=new LinkedHashMap<>();
            item.put("alias",entry.getAlias()); item.put("status",entry.getStatus().name());
            List<Object> differences=new ArrayList<>();
            for(KeyStoreComparison.Difference difference:entry.getDifferences()) {
                Map<String,Object> change=new LinkedHashMap<>();
                change.put("field",difference.getField()); change.put("before",difference.getBefore());
                change.put("after",difference.getAfter()); differences.add(change);
            }
            item.put("differences",differences);
            item.put("before",snapshot(entry.getBefore())); item.put("after",snapshot(entry.getAfter()));
            entries.add(item);
        }
        document.put("entries",entries);
        document.put("certificateRelocations",comparison.getCertificateRelocations());
        StringBuilder out=new StringBuilder(); append(out,document,0); return out.append('\n').toString();
    }
    /** An absent entry is JSON null, distinct from an empty metadata object. */
    private static Object snapshot(List<AnalysisReport> reports) {
        if(reports.isEmpty()) return null;
        Map<String,Object> value=new LinkedHashMap<>();
        value.put("entry",report(reports.get(0)));
        List<Object> certificates=new ArrayList<>();
        for(int i=1;i<reports.size();i++) {
            Map<String,Object> certificate=report(reports.get(i));
            certificate.put("chainIndex",i-1); certificates.add(certificate);
        }
        value.put("certificates",certificates); return value;
    }
    private static Map<String,Object> report(AnalysisReport report) {
        Map<String,Object> value=new LinkedHashMap<>();
        value.put("details",report.getDetails()); value.put("findings",report.getFindings()); return value;
    }
    // Only known maps/lists/strings/integer counts are serialized; arbitrary bean reflection is avoided.
    /** Package-level encoder reused by the deployment report adapter. */
    static String encodeValue(Object value) {
        StringBuilder out=new StringBuilder(); append(out,value,0);return out.toString();
    }
    private static void append(StringBuilder out,Object value,int depth) {
        if(value==null) out.append("null");
        else if(value instanceof Boolean) out.append(value);
        else if(value instanceof Number) out.append(value);
        else if(value instanceof Map) {
            out.append('{'); boolean first=true;
            for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet()) {
                if(!first) out.append(','); first=false; newline(out,depth+1);
                quote(out,String.valueOf(entry.getKey())); out.append(": "); append(out,entry.getValue(),depth+1);
            }
            if(!first) newline(out,depth); out.append('}');
        } else if(value instanceof Iterable) {
            out.append('['); boolean first=true;
            for(Object element:(Iterable<?>)value) {
                if(!first) out.append(','); first=false; newline(out,depth+1); append(out,element,depth+1);
            }
            if(!first) newline(out,depth); out.append(']');
        } else quote(out,String.valueOf(value));
    }
    private static void newline(StringBuilder out,int depth) {
        out.append('\n'); for(int i=0;i<depth;i++) out.append("  ");
    }
    /** Escape controls and surrogate code units, preserving supplementary characters losslessly. */
    private static void quote(StringBuilder out,String text) {
        out.append('"');
        for(char c:text.toCharArray()) {
            switch(c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                default:
                    if(c<0x20 || Character.isSurrogate(c) || c=='\u2028' || c=='\u2029')
                        out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));
                    else out.append(c);
            }
        }
        out.append('"');
    }
}
