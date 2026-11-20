package com.chetankhandave.utility.certificate;

import java.util.*;

/** Adapter composes existing comparison formats with validation outcomes from the same immutable result. */
public final class DeploymentValidationReportFormatter {
    public String format(DeploymentValidationReport report,ComparisonReportFormat format) {
        Objects.requireNonNull(report,"report");Objects.requireNonNull(format,"format");
        if(format==ComparisonReportFormat.JSON) {
            Map<String,Object> data=new LinkedHashMap<>();data.put("status",report.getStatus().name());
            List<Object> checks=new ArrayList<>();
            for(ValidationResult result:report.getResults()) {
                Map<String,Object> check=new LinkedHashMap<>();check.put("name",result.getName());check.put("status",result.getStatus().name());
                List<Object> findings=new ArrayList<>();
                for(ValidationFinding finding:result.getFindings()) {
                    Map<String,Object> item=new LinkedHashMap<>();item.put("ruleId",finding.getRuleId());item.put("status",finding.getStatus().name());
                    item.put("message",finding.getMessage());item.put("required",finding.isRequired());findings.add(item);
                }
                check.put("findings",findings);checks.add(check);
            }
            data.put("checks",checks);
            return "{\n  \"schemaVersion\": \"1.0\",\n  \"comparison\": "+new JsonComparisonReportFormatter().format(report.getComparison()).trim()
                +",\n  \"validation\": "+JsonComparisonReportFormatter.encodeValue(data)+"\n}\n";
        }
        if(format==ComparisonReportFormat.HTML) {
            StringBuilder appendix=new StringBuilder("<section class=\"locations\"><h2>Deployment validation: "+report.getStatus()+"</h2>");
            appendix.append("<p>Comparison scope above describes comparison only; trust results below describe the selected validation policy.</p>");
            for(ValidationResult result:report.getResults()) {
                appendix.append("<h3>").append(HtmlComparisonReportFormatter.escape(result.getName())).append(": ").append(result.getStatus()).append("</h3><ul>");
                for(ValidationFinding finding:result.getFindings()) appendix.append("<li><strong>").append(finding.getStatus()).append("</strong> ")
                    .append(HtmlComparisonReportFormatter.escape(finding.getRuleId())).append(" (required: ").append(finding.isRequired()).append(") — ")
                    .append(HtmlComparisonReportFormatter.escape(finding.getMessage())).append("</li>");
                appendix.append("</ul>");
            }
            appendix.append("</section>");
            return new HtmlComparisonReportFormatter().format(report.getComparison())
                .replace("Trust validation: <strong>NOT_PERFORMED</strong>.","Trust results are reported in the deployment validation section below.")
                .replace("</main>",appendix+"</main>");
        }
        StringBuilder out=new StringBuilder(new TextComparisonReportFormatter().format(report.getComparison()));
        out.append("\nDeployment validation: ").append(report.getStatus()).append('\n');
        for(ValidationResult result:report.getResults()) {
            out.append(TextComparisonReportFormatter.safe(result.getName())).append(": ").append(result.getStatus()).append('\n');
            for(ValidationFinding finding:result.getFindings()) out.append("  ").append(finding.getStatus()).append(" ")
                .append(TextComparisonReportFormatter.safe(finding.getRuleId())).append(" required=").append(finding.isRequired()).append(": ")
                .append(TextComparisonReportFormatter.safe(finding.getMessage())).append('\n');
        }
        return out.toString();
    }
}
