package com.chetankhandave.utility.certificate;

import java.io.Console;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

/** Minimal console adapter; business logic remains usable without a command line. */
public final class CertificateAnalysisCli {
    private CertificateAnalysisCli() { }
    public static void main(String[] args) throws Exception {
        if(args.length>0 && "validate".equals(args[0])) {
            DeploymentValidationCli.main(args);
        } else if(args.length==2 && "certificate".equals(args[0])) {
            CertificateAnalyzer analyzer=new CertificateAnalyzer();
            for(X509Certificate certificate:analyzer.read(Paths.get(args[1]))) System.out.println(analyzer.analyze(certificate));
        } else if((args.length==5 || args.length==6 || args.length==8) && "compare".equals(args[0])) {
            ComparisonReportFormat format=ComparisonReportFormat.TEXT;
            if(args.length==8) {
                if(!"--format".equals(args[6])) throw new IllegalArgumentException("Expected --format TEXT|JSON|HTML after output path");
                format=ComparisonReportFormat.parse(args[7]);
            }
            Console console=System.console();
            if(console==null) throw new IllegalStateException("Use an interactive terminal for password entry, or the Java API");
            char[] oldPassword=console.readPassword("Old store password: ");
            char[] newPassword=null;
            try {
                if(oldPassword==null) throw new IllegalStateException("No old password supplied");
                newPassword=console.readPassword("New store password: ");
                if(newPassword==null) throw new IllegalStateException("No new password supplied");
                KeyStoreComparison comparison=new KeyStoreComparator().compare(Paths.get(args[2]),args[1],oldPassword,
                    Paths.get(args[4]),args[3],newPassword);
                if(args.length>=6) {
                    new ComparisonReportWriter().write(Paths.get(args[5]),comparison,format.formatter());
                    System.out.println("Report saved: "+args[5]);
                } else System.out.print(format.formatter().format(comparison));
            } finally {
                if(oldPassword!=null) Arrays.fill(oldPassword,'\0');
                if(newPassword!=null) Arrays.fill(newPassword,'\0');
            }
        } else if(args.length==4 && "find".equals(args[0])) {
            CertificateAnalyzer analyzer=new CertificateAnalyzer();
            List<X509Certificate> targets=analyzer.read(Paths.get(args[3]));
            if(targets.size()!=1) throw new IllegalArgumentException("Search input must contain exactly one certificate");
            Console console=System.console();
            if(console==null) throw new IllegalStateException("Use an interactive terminal for password entry, or the Java API");
            char[] password=console.readPassword("Store password: ");
            if(password==null) throw new IllegalStateException("No password supplied");
            try {
                List<CertificateMatch> matches=new KeyStoreCertificateFinder(analyzer)
                    .find(Paths.get(args[2]),args[1],password,targets.get(0));
                System.out.println("Certificate found: "+!matches.isEmpty());
                System.out.println("Matches: "+matches.size());
                for(CertificateMatch match:matches) System.out.println(match);
            } finally { Arrays.fill(password,'\0'); }
        } else if(args.length==3 && "keystore".equals(args[0])) {
            Console console=System.console();
            if(console==null) throw new IllegalStateException("Use an interactive terminal for password entry, or the Java API");
            char[] password=console.readPassword("Store password: ");
            if(password==null) throw new IllegalStateException("No password supplied");
            try {
                Map<String,List<AnalysisReport>> reports=new KeyStoreAnalyzer().analyze(Paths.get(args[2]),args[1],password,
                    alias->console.readPassword("Entry password for %s (Ctrl-D skips): ",alias));
                for(Map.Entry<String,List<AnalysisReport>> entry:reports.entrySet()) {
                    System.out.println("Alias: "+entry.getKey());
                    for(AnalysisReport report:entry.getValue()) System.out.println(report);
                }
            } finally { Arrays.fill(password,'\0'); }
        } else {
            System.out.println("Usage: certificate <PEM-or-DER-file> | keystore <JKS|PKCS12> <file> | find <JKS|PKCS12> <store> <certificate> | compare <oldType> <oldStore> <newType> <newStore> [report-file [--format TEXT|JSON|HTML]]");
        }
    }
}
