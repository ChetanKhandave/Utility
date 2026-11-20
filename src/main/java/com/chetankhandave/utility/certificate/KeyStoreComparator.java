package com.chetankhandave.utility.certificate;

import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.*;
import java.util.*;

/** Read-only, alias-based comparison of public store contents, not private/secret key bytes. */
public final class KeyStoreComparator {
    private final Clock clock;
    public KeyStoreComparator() { this(Clock.systemUTC()); }
    public KeyStoreComparator(Clock clock) { this.clock=Objects.requireNonNull(clock,"clock"); }

    public KeyStoreComparison compare(Path before, String beforeType, char[] beforePassword,
            Path after, String afterType, char[] afterPassword)
            throws IOException, GeneralSecurityException {
        return compare(KeyStoreLoader.load(before,beforeType,beforePassword),KeyStoreLoader.load(after,afterType,afterPassword));
    }
    /** Reuse already loaded stores so deployment comparison and validation see the same certificates. */
    KeyStoreComparison compare(KeyStore before,KeyStore after) throws GeneralSecurityException {
        // Capture one instant so validation findings have a consistent reference time.
        CertificateAnalyzer analyzer=new CertificateAnalyzer(Clock.fixed(clock.instant(),ZoneOffset.UTC),Collections.emptyList());
        Map<String,Snapshot> oldEntries=snapshot(before,analyzer);
        Map<String,Snapshot> newEntries=snapshot(after,analyzer);
        SortedSet<String> aliases=new TreeSet<>(oldEntries.keySet()); aliases.addAll(newEntries.keySet());
        List<KeyStoreComparison.Entry> entries=new ArrayList<>();
        for(String alias:aliases) {
            Snapshot old=oldEntries.get(alias), current=newEntries.get(alias);
            List<KeyStoreComparison.Difference> differences=new ArrayList<>();
            KeyStoreComparison.Status status;
            if(old==null) status=KeyStoreComparison.Status.ADDED;
            else if(current==null) status=KeyStoreComparison.Status.REMOVED;
            else {
                compareField("entryType",old.type,current.type,differences);
                compareField("chainLength",String.valueOf(old.der.size()),String.valueOf(current.der.size()),differences);
                if(!old.der.equals(current.der) && old.der.size()==current.der.size()) {
                    List<String> sortedOld=new ArrayList<>(old.der), sortedNew=new ArrayList<>(current.der);
                    Collections.sort(sortedOld); Collections.sort(sortedNew);
                    if(sortedOld.equals(sortedNew)) differences.add(new KeyStoreComparison.Difference("chainOrder","OLD_ORDER","REORDERED"));
                }
                int length=Math.max(old.der.size(),current.der.size());
                for(int i=0;i<length;i++) {
                    String left=i<old.der.size()?old.der.get(i):null;
                    String right=i<current.der.size()?current.der.get(i):null;
                    if(!Objects.equals(left,right)) {
                        Map<String,String> leftDetails=i<old.der.size()?old.reports.get(i+1).getDetails():Collections.emptyMap();
                        Map<String,String> rightDetails=i<current.der.size()?current.reports.get(i+1).getDetails():Collections.emptyMap();
                        // DER is authoritative even if every displayed metadata field is identical.
                        compareField("certificate["+i+"].sha256Fingerprint",leftDetails.get("sha256Fingerprint"),rightDetails.get("sha256Fingerprint"),differences);
                        SortedSet<String> fields=new TreeSet<>(leftDetails.keySet()); fields.addAll(rightDetails.keySet());
                        for(String field:fields) {
                            if(!Arrays.asList("sha256Fingerprint","analyzedAt","remainingWholeDays","validity").contains(field))
                                compareField("certificate["+i+"]."+field,leftDetails.get(field),rightDetails.get(field),differences);
                        }
                        // SHA-256 collisions must not hide different encodings.
                        if(Objects.equals(leftDetails.get("sha256Fingerprint"),rightDetails.get("sha256Fingerprint")))
                            differences.add(new KeyStoreComparison.Difference("certificate["+i+"].encoding","OLD_DER","DIFFERENT_DER"));
                    }
                }
                boolean contentChanged=!differences.isEmpty();
                compareField("entryCreationTime",old.created,current.created,differences);
                status=contentChanged?KeyStoreComparison.Status.CHANGED
                    :!differences.isEmpty()?KeyStoreComparison.Status.METADATA_CHANGED
                    :"SECRET_KEY".equals(old.type)?KeyStoreComparison.Status.NOT_COMPARABLE:KeyStoreComparison.Status.UNCHANGED;
            }
            entries.add(new KeyStoreComparison.Entry(alias,status,differences,
                old==null?Collections.emptyList():old.reports,current==null?Collections.emptyList():current.reports));
        }
        List<String> relocations=new ArrayList<>();
        // Group identical DER encodings, avoiding a quadratic all-certificate scan.
        Map<String,SortedSet<String>> oldLocations=locations(oldEntries), newLocations=locations(newEntries);
        for(Map.Entry<String,SortedSet<String>> item:oldLocations.entrySet()) {
            SortedSet<String> newAliases=newLocations.get(item.getKey());
            if(newAliases!=null && !item.getValue().equals(newAliases)) {
                X509Certificate certificate=oldEntries.get(item.getValue().first()).certificates.get(
                    oldEntries.get(item.getValue().first()).der.indexOf(item.getKey()));
                String fingerprint=analyzer.analyze(certificate).getDetails().get("sha256Fingerprint");
                relocations.add(fingerprint+": aliases "+item.getValue()+" -> "+newAliases+" (not proof of rename)");
            }
        }
        Collections.sort(relocations);
        return new KeyStoreComparison(entries,relocations);
    }
    private static void compareField(String field,String before,String after,List<KeyStoreComparison.Difference> differences) {
        if(!Objects.equals(before,after)) differences.add(new KeyStoreComparison.Difference(field,before,after));
    }
    private static Map<String,SortedSet<String>> locations(Map<String,Snapshot> entries) {
        Map<String,SortedSet<String>> result=new LinkedHashMap<>();
        for(Map.Entry<String,Snapshot> entry:entries.entrySet()) for(String der:entry.getValue().der)
            result.computeIfAbsent(der,k->new TreeSet<>()).add(entry.getKey());
        return result;
    }
    private static Map<String,Snapshot> snapshot(KeyStore store,CertificateAnalyzer analyzer) throws GeneralSecurityException {
        Map<String,Snapshot> result=new TreeMap<>();
        for(String alias:Collections.list(store.aliases())) {
            Snapshot value=new Snapshot();
            value.type=store.entryInstanceOf(alias,KeyStore.PrivateKeyEntry.class)?"PRIVATE_KEY"
                :store.entryInstanceOf(alias,KeyStore.SecretKeyEntry.class)?"SECRET_KEY":"TRUSTED_CERTIFICATE";
            Date date=store.getCreationDate(alias); value.created=date==null?null:date.toInstant().toString();
            Map<String,String> metadata=new LinkedHashMap<>();
            metadata.put("entryType",value.type); metadata.put("entryCreationTime",value.created);
            metadata.put("keyMaterialComparison","NOT_CHECKED");
            value.reports.add(new AnalysisReport(metadata,Collections.emptyList()));
            java.security.cert.Certificate[] chain=store.getCertificateChain(alias);
            java.security.cert.Certificate leaf=store.getCertificate(alias);
            if(chain==null) chain=leaf==null?new java.security.cert.Certificate[0]:new java.security.cert.Certificate[]{leaf};
            for(java.security.cert.Certificate certificate:chain) {
                if(!(certificate instanceof X509Certificate)) throw new KeyStoreException("Only X.509 certificates supported");
                X509Certificate x509=(X509Certificate)certificate;
                value.der.add(Base64.getEncoder().encodeToString(x509.getEncoded()));
                value.certificates.add(x509); value.reports.add(analyzer.analyze(x509));
            }
            result.put(alias,value);
        }
        return result;
    }
    private static final class Snapshot {
        String type,created;
        final List<String> der=new ArrayList<>();
        final List<X509Certificate> certificates=new ArrayList<>();
        final List<AnalysisReport> reports=new ArrayList<>();
    }
}
