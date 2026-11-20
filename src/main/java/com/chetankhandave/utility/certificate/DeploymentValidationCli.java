package com.chetankhandave.utility.certificate;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Console adapter for policy-based deployment checks; passwords are prompted, cleared and never serialized. */
public final class DeploymentValidationCli {
    private DeploymentValidationCli() { }
    public static void main(String[] args) throws Exception {
        if(args.length!=11 || !"validate".equals(args[0]) || !"--format".equals(args[9]))
            throw new IllegalArgumentException("validate <oldType> <oldStore> <newType> <newStore> <trustType> <trustStore> <policy.properties> <report> --format TEXT|JSON|HTML");
        ComparisonReportFormat format=ComparisonReportFormat.parse(args[10]);Properties properties=new Properties();
        try(Reader reader=Files.newBufferedReader(Paths.get(args[7]),StandardCharsets.UTF_8)) { properties.load(reader); }
        DeploymentValidationPolicy policy=DeploymentValidationPolicy.fromProperties(properties);
        Console console=System.console();if(console==null) throw new IllegalStateException("Use an interactive terminal, or DeploymentValidationService API");
        char[] before=null,after=null,trust=null;
        ValidationStatus status;
        try {
            before=console.readPassword("Old store password: ");after=console.readPassword("New store password: ");trust=console.readPassword("Truststore password: ");
            if(before==null || after==null || trust==null) throw new IllegalStateException("All store passwords are required");
            DeploymentValidationReport report=new DeploymentValidationService().validate(Paths.get(args[2]),args[1],before,Paths.get(args[4]),args[3],after,
                Paths.get(args[6]),args[5],trust,policy);
            String text=new DeploymentValidationReportFormatter().format(report,format);
            Files.write(Paths.get(args[8]),text.getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
            System.out.println("Validation: "+report.getStatus()+"; report saved: "+args[8]);
            status=report.getStatus();
        } finally {
            // Clear secrets before returning a nonzero process status.
            if(before!=null) Arrays.fill(before,'\0');if(after!=null) Arrays.fill(after,'\0');if(trust!=null) Arrays.fill(trust,'\0');
        }
        if(status!=ValidationStatus.PASS) System.exit(2);
    }
}
